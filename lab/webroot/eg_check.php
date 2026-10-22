<?php
// Post-OOM state check
// Reports PID and tries to detect if any stale objects survived from previous requests

$pid = getmypid();

echo "PID: $pid\n";
echo "SAPI: " . php_sapi_name() . "\n";

// Check EG(objects_store) count via get_defined_vars / object counting
// On a fresh request, there should be zero user objects
echo "num_objects: " . (function() {
    // gc_status gives us info about the garbage collector state
    $gc = gc_status();
    return "roots={$gc['roots']},runs={$gc['runs']},collected={$gc['collected']}";
})() . "\n";

// Check if destruct log exists from a previous request
$log = "/tmp/eg_destruct.log";
if (file_exists($log)) {
    echo "destruct_log_size: " . filesize($log) . "\n";
    echo "destruct_log_tail: " . trim(shell_exec("tail -5 $log")) . "\n";
} else {
    echo "destruct_log: none\n";
}

// Check for any error state carried over
echo "last_error: " . json_encode(error_get_last()) . "\n";

// Memory state
echo "memory_usage: " . memory_get_usage(true) . "\n";
echo "peak_memory: " . memory_get_peak_usage(true) . "\n";

echo "OK\n";
