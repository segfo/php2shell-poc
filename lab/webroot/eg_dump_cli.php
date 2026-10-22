<?php
// Dump EG(objects_store) and PS() from a specific worker PID
// Run via: docker exec php2shell-apache php /var/www/html/eg_dump_cli.php <PID>

if ($argc < 2) {
    echo "Usage: php eg_dump_cli.php <PID>\n";
    exit(1);
}

$pid = (int)$argv[1];
echo "PID: $pid\n";

$maps = file_get_contents("/proc/$pid/maps");
$base = null;
foreach (explode("\n", $maps) as $line) {
    if (strpos($line, "libphp.so") !== false && strpos($line, "r--p") !== false && $base === null) {
        $base = hexdec(explode("-", $line)[0]);
    }
}
if (!$base) { echo "No libphp.so\n"; exit(1); }
echo "libphp: 0x" . dechex($base) . "\n";

$mem = fopen("/proc/$pid/mem", "rb");
if (!$mem) { echo "Cannot open mem\n"; exit(1); }

// executor_globals at offset 0xf4f900
$eg_addr = $base + 0xf4f900;

// First, find the offset of objects_store within executor_globals
// In PHP 8.2, struct _zend_executor_globals has objects_store
// We need to find the exact offset. objects_store is a zend_objects_store struct:
//   typedef struct _zend_objects_store {
//     zend_object **object_buckets;
//     uint32_t top;
//     uint32_t size;
//     int free_list_head;
//   };

// The offset varies by PHP version and build options.
// Let's dump a larger range and look for patterns.
// objects_store typically appears after the hashtable fields and error handling.

echo "\n=== Full EG dump (first 1024 bytes) ===\n";
fseek($mem, $eg_addr);
$eg_raw = fread($mem, 1024);

// Dump all non-zero qwords with annotations
for ($off = 0; $off < 1024; $off += 8) {
    $v = unpack("P", substr($eg_raw, $off, 8))[1];
    if ($v == 0) continue;
    $hex = sprintf("0x%016x", $v);
    $note = "";
    if ($v > 0x7f0000000000 && $v < 0x800000000000) $note = "(lib/mmap)";
    elseif ($v > 0x5500000000 && $v < 0x600000000000) $note = "(heap)";
    elseif ($v < 0x10000) $note = "(small int/flag)";
    echo sprintf("  EG+0x%03x: %s %s\n", $off, $hex, $note);
}

// Now let's specifically look for objects_store by searching for the pattern:
// pointer (object_buckets) + uint32_t (top) + uint32_t (size) + int32 (free_list_head)
// object_buckets should be a heap pointer, top and size should be small numbers
echo "\n=== Candidate objects_store locations ===\n";
for ($off = 0; $off < 1016; $off += 8) {
    $ptr = unpack("P", substr($eg_raw, $off, 8))[1];
    if ($ptr == 0) continue;
    // Check if it could be a pointer to heap
    if ($ptr < 0x5500000000 || $ptr > 0x800000000000) continue;

    // Next 8 bytes: top (uint32) + size (uint32)
    $vals = unpack("V2", substr($eg_raw, $off + 8, 8));
    $top = $vals[1];
    $size = $vals[2];

    // objects_store: top is number of objects, size is capacity
    // Typically 1-1000 for top, power-of-2 for size
    if ($top > 0 && $top <= 10000 && $size >= $top && $size <= 65536) {
        // Next 4 bytes: free_list_head (int32)
        $flh = unpack("l", substr($eg_raw, $off + 16, 4))[1];
        echo sprintf("  EG+0x%03x: ptr=0x%x top=%d size=%d free_list_head=%d  *** LIKELY objects_store ***\n",
            $off, $ptr, $top, $size, $flh);
    }
}

// ps_globals dump
$ps_addr = $base + 0xf39120;
echo "\n=== PS() globals (first 256 bytes) ===\n";
fseek($mem, $ps_addr);
$ps_raw = fread($mem, 256);
for ($off = 0; $off < 256; $off += 8) {
    $v = unpack("P", substr($ps_raw, $off, 8))[1];
    if ($v == 0) continue;
    $hex = sprintf("0x%016x", $v);
    $note = "";
    if ($v == 1) $note = "(session_none)";
    elseif ($v == 2) $note = "(session_active)";
    elseif ($v > 0x7f0000000000 && $v < 0x800000000000) $note = "(lib)";
    elseif ($v > 0x5500000000 && $v < 0x600000000000) $note = "(heap)";
    echo sprintf("  PS+0x%03x: %s %s\n", $off, $hex, $note);
}

fclose($mem);
