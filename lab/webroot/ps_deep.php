<?php
header("Content-Type: text/plain");
echo "PID: " . getmypid() . "\n";
echo "session_status(): " . session_status() . "\n\n";

if (isset($_SESSION)) {
    echo "[+] \$_SESSION is set!\n";
    echo "Type: " . gettype($_SESSION) . "\n";
    echo "Count: " . (is_array($_SESSION) ? count($_SESSION) : "N/A") . "\n\n";

    if (is_array($_SESSION)) {
        foreach ($_SESSION as $key => $val) {
            $type = gettype($val);
            echo "KEY: $key\n";
            echo "  type: $type\n";
            if (is_object($val)) {
                echo "  class: " . get_class($val) . "\n";
                if (get_class($val) === '__PHP_Incomplete_Class') {
                    echo "  [!!!] INCOMPLETE CLASS OBJECT\n";
                    echo "  properties: " . print_r((array)$val, true) . "\n";
                }
            } elseif (is_array($val)) {
                echo "  count: " . count($val) . "\n";
                // Show first few entries
                $i = 0;
                foreach ($val as $k2 => $v2) {
                    if ($i >= 5) { echo "  ...\n"; break; }
                    $t2 = gettype($v2);
                    if (is_object($v2)) {
                        echo "  [$k2] => object(" . get_class($v2) . ")\n";
                    } else {
                        $s = is_string($v2) ? substr($v2, 0, 100) : var_export($v2, true);
                        echo "  [$k2] => ($t2) $s\n";
                    }
                    $i++;
                }
            } elseif (is_string($val)) {
                echo "  value: " . substr($val, 0, 200) . "\n";
            } else {
                echo "  value: " . var_export($val, true) . "\n";
            }
            echo "\n";
        }
    }

    // Check for any registered shutdown functions
    echo "Checking for type confusion opportunities:\n";
    foreach ($_SESSION as $key => $val) {
        if (is_object($val)) {
            echo "  Object '$key': class=" . get_class($val) . "\n";
            // Try to trigger methods
            echo "  Has __toString: " . (method_exists($val, '__toString') ? 'yes' : 'no') . "\n";
            echo "  Has __destruct: " . (method_exists($val, '__destruct') ? 'yes' : 'no') . "\n";
        }
    }
} else {
    echo "[-] \$_SESSION is NOT set\n";
}

// Check if we can see stale session data via session functions
echo "\nAttempting session_start():\n";
if (session_status() !== PHP_SESSION_ACTIVE) {
    // Note: if PS(session_status) is stale, this might behave unexpectedly
    $result = @session_start();
    echo "  session_start() returned: " . var_export($result, true) . "\n";
    echo "  session_status(): " . session_status() . "\n";
    echo "  session_id(): " . session_id() . "\n";
    if (isset($_SESSION)) {
        echo "  \$_SESSION count: " . count($_SESSION) . "\n";
    }
}

echo "\nMemory: peak=" . memory_get_peak_usage(true) . " current=" . memory_get_usage(true) . "\n";
