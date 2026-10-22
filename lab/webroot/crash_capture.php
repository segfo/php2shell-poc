<?php
// Enable core dumps 
ini_set("error_reporting", E_ALL);

// Write our PID
$pid = getmypid();
file_put_contents("/tmp/crash_pid", "$pid\n", FILE_APPEND);

// session_start should trigger the crash path
session_start();
echo "PID: $pid survived\n";
echo "session_status: " . session_status() . "\n";
if (isset($_SESSION)) {
    echo "SESSION keys: " . implode(",", array_keys($_SESSION)) . "\n";
    foreach ($_SESSION as $k => $v) {
        if (is_object($v)) {
            echo "  $k => object(" . get_class($v) . ")\n";
        }
    }
}
echo "OK\n";
