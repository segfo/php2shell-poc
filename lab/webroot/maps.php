<?php
header("Content-Type: text/plain");
$maps = @file_get_contents("/proc/self/maps");
if ($maps) {
    foreach (explode("\n", $maps) as $line) {
        if (strpos($line, "r-xp") !== false || strpos($line, "r--p") !== false) {
            echo $line . "\n";
        }
    }
} else {
    echo "Cannot read /proc/self/maps\n";
    echo "PID: " . getmypid() . "\n";
}
