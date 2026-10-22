<?php
session_start();
$maps = file_get_contents('/proc/self/maps');
$anon = [];
foreach (explode("\n", $maps) as $line) {
    if (preg_match('/^([0-9a-f]+)-([0-9a-f]+)\s+rw-p\s+00000000\s+00:00\s+0\s*$/', $line, $m)) {
        $start = hexdec($m[1]);
        $end = hexdec($m[2]);
        $size = $end - $start;
        if ($size >= 0x200000) { // 2MB+ = likely ZMM chunk
            $anon[] = sprintf('0x%x-0x%x (%dMB)', $start, $end, $size / 1048576);
        }
    }
}
echo 'ZMM chunks (2MB+): ' . implode(', ', $anon) . "\n";
echo 'memory_get_usage(true): ' . memory_get_usage(true) . "\n";

// Allocate some objects to see where they land
$objs = [];
for ($i = 0; $i < 5; $i++) {
    $o = new stdClass;
    $o->data = str_repeat('B', 64);
    $objs[] = $o;
}
echo 'After 5 objects, memory_get_usage(true): ' . memory_get_usage(true) . "\n";
