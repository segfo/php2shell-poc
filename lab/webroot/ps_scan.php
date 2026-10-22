<?php
$maps = file_get_contents("/proc/self/maps");
preg_match("/^([0-9a-f]+)-.*libphp/m", $maps, $m);
$libphp_base = hexdec($m[1]);
$ps_addr = $libphp_base + 0xf39120;
$eg_addr = $libphp_base + 0xf4f900;

echo "libphp_base=0x" . dechex($libphp_base) . "\n";
echo "PS_ADDR=0x" . dechex($ps_addr) . "\n";
echo "EG_ADDR=0x" . dechex($eg_addr) . "\n";

function dump_mem($addr, $size, $label) {
    $f = fopen("/proc/self/mem", "rb");
    fseek($f, $addr);
    $data = fread($f, $size);
    fclose($f);
    echo "\n=== $label (0x" . dechex($addr) . ") ===\n";
    for ($i = 0; $i < strlen($data); $i += 8) {
        $val = unpack("P", substr($data, $i, 8))[1];
        printf("  +0x%03x: 0x%016x\n", $i, $val);
    }
}

echo "\n--- BEFORE session_start ---\n";
echo "session_status()=" . session_status() . "\n";
dump_mem($ps_addr, 256, "PS BEFORE");

session_id("scantest00000000000000000");
session_start();

echo "\n--- AFTER session_start ---\n";
echo "session_status()=" . session_status() . "\n";
dump_mem($ps_addr, 256, "PS ACTIVE");

session_write_close();
echo "\n--- AFTER session_write_close ---\n";
echo "session_status()=" . session_status() . "\n";
dump_mem($ps_addr, 256, "PS CLOSED");
