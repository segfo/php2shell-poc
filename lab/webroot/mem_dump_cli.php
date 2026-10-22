<?php
// CLI script to dump ps_globals from an Apache worker's memory
// Run as: php /var/www/html/mem_dump_cli.php <PID>
// Must be run as root (which docker exec does by default)

if ($argc < 2) {
    echo "Usage: php mem_dump_cli.php <PID>\n";
    exit(1);
}

$pid = (int)$argv[1];
echo "Target PID: $pid\n";

$maps = file_get_contents("/proc/$pid/maps");
if (!$maps) {
    echo "ERROR: cannot read /proc/$pid/maps\n";
    exit(1);
}

$base = null;
foreach (explode("\n", $maps) as $line) {
    if (strpos($line, "libphp.so") !== false && strpos($line, "r--p") !== false && $base === null) {
        $base = hexdec(explode("-", $line)[0]);
    }
}

if ($base === null) {
    echo "ERROR: no libphp.so found in maps\n";
    exit(1);
}

echo "libphp base: 0x" . dechex($base) . "\n";

$mem = fopen("/proc/$pid/mem", "rb");
if (!$mem) {
    echo "ERROR: cannot open /proc/$pid/mem\n";
    exit(1);
}

// Verify ELF header
fseek($mem, $base);
$hdr = fread($mem, 4);
echo "ELF magic: " . bin2hex($hdr) . " (" . ($hdr === "\x7fELF" ? "VALID" : "INVALID") . ")\n";

// ps_globals at offset 0xf39120
$ps_addr = $base + 0xf39120;
echo "\nps_globals at: 0x" . dechex($ps_addr) . "\n";
fseek($mem, $ps_addr);
$ps_raw = fread($mem, 256);
echo "Read " . strlen($ps_raw) . " bytes\n\n";

if (strlen($ps_raw) >= 128) {
    $ptrs = unpack("P16", $ps_raw);
    for ($i = 1; $i <= 16; $i++) {
        $v = $ptrs[$i];
        $hex = sprintf("0x%016x", $v);
        $note = "";
        if ($v == 0) $note = " (NULL)";
        elseif ($v == 1) $note = " (php_session_none)";
        elseif ($v == 2) $note = " (php_session_active)";
        elseif ($v > 0x7f0000000000 && $v < 0x800000000000) $note = " (looks like pointer)";
        elseif ($v > 0x5500000000 && $v < 0x600000000000) $note = " (heap?)";
        echo sprintf("  PS+0x%03x: %s%s\n", ($i-1)*8, $hex, $note);
    }
}

// executor_globals at offset 0xf4f900
$eg_addr = $base + 0xf4f900;
echo "\nexecutor_globals at: 0x" . dechex($eg_addr) . "\n";
fseek($mem, $eg_addr);
$eg_raw = fread($mem, 512);

if (strlen($eg_raw) >= 512) {
    echo "Selected EG fields:\n";
    // EG(objects_store) is typically around offset 0x1c0-0x200
    for ($off = 0; $off < 512; $off += 8) {
        $v = unpack("P", substr($eg_raw, $off, 8))[1];
        if ($v == 0) continue; // skip nulls for brevity
        $hex = sprintf("0x%016x", $v);
        $note = "";
        if ($v > 0x7f0000000000 && $v < 0x800000000000) $note = " (lib ptr)";
        elseif ($v > 0x5500000000 && $v < 0x600000000000) $note = " (heap?)";
        echo sprintf("  EG+0x%03x: %s%s\n", $off, $hex, $note);
    }
}

fclose($mem);
echo "\nDone.\n";
