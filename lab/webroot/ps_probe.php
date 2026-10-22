<?php
header("Content-Type: text/plain");

$pid = getmypid();
echo "PID: $pid\n";

$maps = @file_get_contents("/proc/self/maps");
$libphp_base = null;

foreach (explode("\n", $maps) as $line) {
    if (strpos($line, "libphp.so") !== false && $libphp_base === null) {
        $parts = explode("-", $line);
        $libphp_base = hexdec($parts[0]);
        echo "libphp base: 0x" . dechex($libphp_base) . "\n";
    }
}

if ($libphp_base === null) {
    echo "ERROR: could not find libphp.so\n";
    exit(1);
}

// From nm -D: ps_globals at 0xf39120, executor_globals at 0xf4f900
$ps_globals_addr = $libphp_base + 0xf39120;
$eg_addr = $libphp_base + 0xf4f900;
echo "ps_globals addr: 0x" . dechex($ps_globals_addr) . "\n";
echo "executor_globals addr: 0x" . dechex($eg_addr) . "\n";

// Read memory using pack/unpack trick via FFI if available, else via file
// Try reading through /proc/self/mem with binary mode
$mem = @fopen("/proc/self/mem", "rb");
if ($mem) {
    echo "Using /proc/self/mem\n";
} else {
    // Fallback: use FFI to peek at memory
    if (extension_loaded('ffi')) {
        echo "Using FFI\n";
    } else {
        echo "Neither /proc/self/mem nor FFI available\n";
        echo "Trying alternative: read via unpack of known pointer...\n";
    }
}

// Use session_status() to check PS(session_status) indirectly
echo "\nsession_status(): " . session_status() . "\n";
echo "  (0=disabled, 1=none, 2=active)\n";

// Check if session is somehow already active (stale state!)
if (session_status() === PHP_SESSION_ACTIVE) {
    echo "  [!!!] SESSION IS ACTIVE WITHOUT session_start()!\n";
    echo "  session_id: " . session_id() . "\n";
    echo "  \$_SESSION: " . print_r($_SESSION, true) . "\n";
}

// Check $_SESSION superglobal (should be undefined without session_start)
echo "\n\$_SESSION exists: " . (isset($_SESSION) ? "YES" : "NO") . "\n";
if (isset($_SESSION)) {
    echo "  [!!!] \$_SESSION populated without session_start()!\n";
    echo "  Type: " . gettype($_SESSION) . "\n";
    echo "  Count: " . count($_SESSION) . "\n";
    $dump = print_r($_SESSION, true);
    echo "  Content (first 500): " . substr($dump, 0, 500) . "\n";
}

// Check for __PHP_Incomplete_Class objects in $_SESSION
if (isset($_SESSION) && is_array($_SESSION)) {
    foreach ($_SESSION as $k => $v) {
        if (is_object($v) && get_class($v) === '__PHP_Incomplete_Class') {
            echo "  [!!!] INCOMPLETE CLASS in \$_SESSION[$k]!\n";
        }
    }
}

// Check error handlers (stale from previous request?)
$prev_error = set_error_handler(function() {});
restore_error_handler();
echo "\nPrevious error handler: " . ($prev_error ? "SET (" . (is_string($prev_error) ? $prev_error : "closure/array") . ")" : "NONE") . "\n";

$prev_exception = set_exception_handler(function($e) {});
restore_exception_handler();
echo "Previous exception handler: " . ($prev_exception ? "SET" : "NONE") . "\n";

// Session files on disk
echo "\nSession files:\n";
$files = glob("/tmp/sess_*");
if ($files) {
    foreach ($files as $f) {
        $size = filesize($f);
        $mtime = filemtime($f);
        echo "  $f: $size bytes, mtime=" . date("H:i:s", $mtime) . "\n";
    }
} else {
    echo "  (none)\n";
}

// Check environment for signs of previous OOM
echo "\nMemory:\n";
echo "  memory_limit: " . ini_get('memory_limit') . "\n";
echo "  peak usage: " . memory_get_peak_usage(true) . "\n";
echo "  current: " . memory_get_usage(true) . "\n";
