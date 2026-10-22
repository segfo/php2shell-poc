<?php
header("Content-Type: text/plain");

$pid = getmypid();
echo "PID: $pid\n";
echo "SAPI: " . php_sapi_name() . "\n";

// Key question: was session_start() called before this script?
// In mod_php with upload_progress, rfc1867 callback calls
// php_session_start() during SAPI input parsing, BEFORE RINIT.
// After OOM bailout on previous request, PS() may be stale.

$status = session_status();
echo "session_status(): $status";
if ($status == PHP_SESSION_NONE) echo " (none)";
if ($status == PHP_SESSION_ACTIVE) echo " (ACTIVE!)";
if ($status == PHP_SESSION_DISABLED) echo " (disabled)";
echo "\n";

echo "session_id(): '" . session_id() . "'\n";

// $_SESSION check - the rfc1867 callback populates this
echo "\n=== \$_SESSION STATE ===\n";
echo "isset(\$_SESSION): " . (isset($_SESSION) ? "YES" : "NO") . "\n";

if (isset($_SESSION)) {
    echo "count(\$_SESSION): " . count($_SESSION) . "\n";
    foreach ($_SESSION as $key => $val) {
        $type = gettype($val);
        echo "\n  KEY: '$key' ($type)\n";
        if (is_array($val)) {
            echo "  count: " . count($val) . "\n";
            foreach ($val as $k => $v) {
                if (is_object($v)) {
                    $cls = get_class($v);
                    echo "    [$k] => object($cls)\n";
                    if ($cls === '__PHP_Incomplete_Class') {
                        echo "    [!!!] __PHP_Incomplete_Class detected!\n";
                        $props = (array)$v;
                        foreach ($props as $pk => $pv) {
                            $pk_clean = preg_replace('/[^\x20-\x7e]/', '.', $pk);
                            echo "      prop '$pk_clean' => " . var_export($pv, true) . "\n";
                        }
                    }
                } else {
                    $sv = is_string($v) ? "'" . substr($v, 0, 80) . "'" : var_export($v, true);
                    echo "    [$k] => ($type) $sv\n";
                }
            }
        } elseif (is_object($val)) {
            $cls = get_class($val);
            echo "  class: $cls\n";
            if ($cls === '__PHP_Incomplete_Class') {
                echo "  [!!!] __PHP_Incomplete_Class at top level!\n";
                $props = (array)$val;
                foreach ($props as $pk => $pv) {
                    $pk_clean = preg_replace('/[^\x20-\x7e]/', '.', $pk);
                    echo "    prop '$pk_clean' => " . var_export($pv, true) . "\n";
                }
            }
        } else {
            echo "  value: " . var_export($val, true) . "\n";
        }
    }
}

// Check if there are session files with injected objects
echo "\n=== SESSION FILES ===\n";
$files = glob("/tmp/sess_*");
foreach ($files as $f) {
    $data = file_get_contents($f);
    $size = strlen($data);
    $has_object = (strpos($data, 'O:') !== false) ? "HAS_OBJECTS" : "no_objects";
    $has_class = (strpos($data, '__PHP_Incomplete_Class') !== false) ? "HAS_INCOMPLETE" : "";
    echo basename($f) . ": {$size}B $has_object $has_class\n";
    if ($size < 2000) {
        echo "  content: " . substr($data, 0, 500) . "\n";
    }
}

echo "\nMemory: " . memory_get_usage(true) . " / " . ini_get('memory_limit') . "\n";
