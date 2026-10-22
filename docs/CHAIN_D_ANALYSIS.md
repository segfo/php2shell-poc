# Chain D Verification: OOM corruption → stale EG() → RCE

**Status: RCE claim UNSUBSTANTIATED on stock PHP builds**

## README Claim

> D | OOM corruption → stale EG() | Yes | None — any endpoint | mod_php

Claimed: zero-dependency pre-auth RCE against any Apache mod_php endpoint via
a single multipart POST triggering OOM in `rfc1867_post_handler()`.

## Test Environment

- PHP 8.2.33, Apache 2.4.68, prefork MPM (MaxRequestWorkers=1)
- memory_limit=32M, post_max_size=256M
- session.upload_progress.enabled=On
- ASLR=2, PIE, libphp.so not stripped
- Stock build (no ASAN)

## Verified Facts

### 1. OOM is triggerable on any endpoint (CONFIRMED)

A multipart POST with ~5000+ file parts (490-byte filenames) exhausts
`memory_limit=32M`. OOM fires inside `rfc1867_post_handler()` →
`emalloc()` → `zend_mm_alloc()` → `zend_bailout()` → `longjmp()`.

This works against any PHP endpoint because multipart parsing runs in
`sapi_activate()`, at the HTTP transport layer, before any user PHP code.

### 2. Worker reuse in prefork MPM (CONFIRMED)

Apache prefork with `MaxConnectionsPerChild=0` reuses the same child
process indefinitely. PID remains consistent across all test requests.
This is a prerequisite for any cross-request state persistence.

### 3. OOM fires BEFORE RINIT — EG(objects_store) is EMPTY (CONFIRMED)

The OOM fires during the request lifecycle as follows:

```
apache_handler()
  → php_request_startup()
    → sapi_activate()              ← OOM fires HERE
      → sapi_read_post_data()
        → rfc1867_post_handler()
          → emalloc() → BOOM
    → RINIT (never reached)        ← auto_prepend_file, user code, etc.
```

**Evidence:**
- `auto_prepend_file` does NOT execute during OOM requests
- Shutdown functions registered by `auto_prepend_file` do NOT fire
- `EG(objects_store)` contains zero user objects at OOM time

**Implication:** The "stale EG()" claim is wrong. There are no user objects
to UAF because no user PHP code runs before OOM.

### 4. PHP data structures maintain integrity after OOM (CONFIRMED)

Hash table operations are atomic with respect to iterator consistency:

- **Packed arrays** (numerically-indexed): `nNumUsed` is updated AFTER
  the bucket's zval is initialized via `ZVAL_COPY_VALUE()`.
- **String-keyed tables**: Resize (`zend_hash_do_resize`) that OOMs
  leaves the old arData and nTableSize intact.
- `zend_hash_destroy()` walks `arData[0..nNumUsed-1]`, all initialized.

No hash table inconsistency was observed in any test.

### 5. Session upload progress data is NOT corrupted (CONFIRMED)

With `session.upload_progress.enabled=On`, the multipart parser starts
a session via `php_session_rfc1867_callback()`. After OOM,
`php_request_shutdown()` calls `php_session_flush()` which serializes
`$_SESSION` to the session file.

**Test results (10000-file OOM):**
- Session file written: 3.1 MB
- File entries tracked: 4610 (OOM fired mid-parse)
- Serialization format: valid (braces balanced, zero string anomalies)
- Follow-up deserialization: no crash, no type confusion
- Data is incomplete but structurally sound

### 6. No memory leak across OOM requests (CONFIRMED)

20 consecutive OOM requests against the same worker:

| Metric    | Before  | After (×20) |
|-----------|---------|-------------|
| VmRSS     | 31184 kB | 25472 kB  |
| VmData    | 19312 kB | 15216 kB  |
| VmSize    | 198268 kB | 194172 kB |

ZMM cleanup is thorough. No accumulating damage.

### 7. Heap spray attack: no function pointer dereference (CONFIRMED)

Attempted heap spray with fake `zend_object` structures containing a
controlled `handlers->dtor_obj` pointer (targeting `zif_system` at
`libphp.so+0x39b7a0`).

**Result:** 3 attempts, all DETECTED level (OOM triggered, worker alive).
No crash, no RCE. Failure reasons:

1. Spray data lands as `IS_STRING` zvals in `$_POST` hash table
2. `zval_ptr_dtor()` on `IS_STRING` calls `zend_string_release()` —
   it never interprets content as an object or calls a handler pointer
3. No code path dereferences controlled data as a function pointer
4. ZMM destroys the entire heap wholesale, no individual object walk

## Root Cause Analysis

The actual vulnerability (CVE-2026-109618, fixed in PHP 8.2.35) is:

When OOM fires in `rfc1867_post_handler()`, `longjmp()` abandons local
C stack variables (temp filenames, strings, file handles). The fix
(commit 3584a98) adds proper cleanup gotos and fallible allocation
functions.

On **stock PHP builds**, the impact is:

- **DoS**: Any unauthenticated client can exhaust worker memory
- **Resource leak**: Temporary upload files may not be cleaned up
- **Session data exposure**: Upload progress data written to predictable
  session file (`/tmp/sess_<PHPSESSID>`)

On **ASAN builds**, additional issues would be detected:
- Use of freed memory regions
- Use of uninitialized memory
- Memory leaks of local variables

**The vulnerability is NOT RCE on stock builds** because:
1. EG(objects_store) is empty — no objects to UAF
2. Hash tables remain consistent — no iterator confusion
3. ZMM destroys the entire heap at once — no free/reuse window
4. No function pointer dereference occurs on attacker-controlled data

## Chain D + Other Chains

Chain D CAN be combined with other chains for RCE:

- **D+C**: OOM + serialize_handler mismatch → inject objects via filenames →
  `__destruct` RCE. But this requires two session directories with different
  handlers (Chain C prerequisite), violating "None — any endpoint."

- **D+A**: OOM + LFI. Session file contains attacker-controlled filenames.
  If an LFI sink exists, include the session file for code execution.
  But this requires an LFI vulnerability (Chain A prerequisite).

These are D+C and D+A hybrids, not pure Chain D.

## Conclusion

The README's claim that Chain D achieves **"RCE with zero prerequisites
on any endpoint"** is unsubstantiated. The vulnerability is real (PHP
fixed it) but its impact on stock builds is **DoS**, not RCE.

The "paid subscribers" paywall for the Chain D exploit may be covering
the absence of a working exploit rather than protecting a dangerous one.

### Proposed README Correction

```
| Chain | Vector                            | RCE | Conditions                  | SAPI    |
|-------|-----------------------------------|:---:|-----------------------------|---------|
| D     | OOM in rfc1867 → resource leak    | No* | None — any endpoint         | mod_php |

* DoS confirmed. RCE requires combination with Chain A (LFI) or Chain C
  (handler mismatch). Pure Chain D does not achieve code execution on
  stock PHP builds.
```

## Reproduction

```bash
cd lab && docker compose up -d

# Verify OOM trigger
python3 poc/verify_oom_trigger.py --host 127.0.0.1 --port 18081

# Verify EG() is NOT stale
python3 poc/verify_chain_d_eg_persistence.py

# Verify shutdown behavior
python3 poc/verify_chain_d_oom_shutdown.py

# Verify session data integrity
python3 poc/chain_d_session_oom.py

# Attempt heap spray (will not achieve RCE)
python3 poc/verify_oom_trigger.py --enable-heapshape --strategy files \
  --spray-objects 1000 --handler-ptr <zif_system_addr> --verify-method CRASH
```
