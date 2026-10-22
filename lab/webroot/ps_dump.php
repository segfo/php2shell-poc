<?php
// Dump PS globals state
echo 'session_status: ' . session_status() . "\n";
echo 'session_id: ' . session_id() . "\n";
echo 'session_name: ' . session_name() . "\n";
echo 'save_path: ' . session_save_path() . "\n";
echo 'module_name: ' . session_module_name() . "\n";

// Try to see if we can start a session
$result = @session_start();
echo 'session_start result: ' . var_export($result, true) . "\n";
echo 'session_id after start: ' . session_id() . "\n";
echo 'session_status after start: ' . session_status() . "\n";

if (isset($_SESSION)) {
    echo 'SESSION keys: ' . implode(', ', array_keys($_SESSION)) . "\n";
    foreach ($_SESSION as $k => $v) {
        echo "  $k: " . (is_object($v) ? get_class($v) : gettype($v)) . "\n";
    }
}
