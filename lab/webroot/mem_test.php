<?php
header("Content-Type: text/plain");
error_reporting(E_ALL);
echo "PID: " . getmypid() . "\n";
echo "UID: " . posix_getuid() . " GID: " . posix_getgid() . "\n";

$stat = @stat("/proc/self/mem");
if ($stat) {
    echo "stat /proc/self/mem: mode=" . decoct($stat['mode']) . " uid=" . $stat['uid'] . "\n";
}

$f = @fopen("/proc/self/mem", "rb");
if ($f) {
    echo "fopen: OK\n";
    $maps = file_get_contents("/proc/self/maps");
    $base = null;
    foreach (explode("\n", $maps) as $line) {
        if (strpos($line, "libphp.so") !== false && strpos($line, "r--p") !== false && $base === null) {
            $base = hexdec(explode("-", $line)[0]);
        }
    }
    if ($base) {
        echo "libphp base: 0x" . dechex($base) . "\n";
        fseek($f, $base);
        $header = fread($f, 4);
        echo "ELF magic: " . bin2hex($header) . " (" . ($header === "\x7fELF" ? "VALID" : "INVALID") . ")\n";

        $ps_addr = $base + 0xf39120;
        echo "\nps_globals at: 0x" . dechex($ps_addr) . "\n";
        fseek($f, $ps_addr);
        $ps_raw = fread($f, 256);
        if ($ps_raw && strlen($ps_raw) >= 64) {
            echo "ps_globals read: " . strlen($ps_raw) . " bytes\n\n";
            $ptrs = unpack("P32", $ps_raw);
            for ($i = 1; $i <= 16; $i++) {
                $v = $ptrs[$i];
                $hex = sprintf("0x%016x", $v);
                $note = "";
                if ($v == 0) $note = " (NULL)";
                elseif ($v == 1) $note = " (php_session_none)";
                elseif ($v == 2) $note = " (php_session_active)";
                elseif ($v > 0x7f0000000000 && $v < 0x800000000000) $note = " (looks like pointer)";
                echo sprintf("  PS+0x%03x: %s%s\n", ($i-1)*8, $hex, $note);
            }
        } else {
            echo "ps_globals read FAILED: got " . strlen($ps_raw) . " bytes\n";
        }

        echo "\nexecutor_globals (selected fields):\n";
        $eg_addr = $base + 0xf4f900;
        fseek($f, $eg_addr);
        $eg_raw = fread($f, 512);
        if ($eg_raw && strlen($eg_raw) >= 256) {
            for ($off = 0x1c0; $off <= 0x210; $off += 8) {
                $v = unpack("P", substr($eg_raw, $off, 8))[1];
                $hex = sprintf("0x%016x", $v);
                $note = "";
                if ($v == 0) $note = " (NULL)";
                elseif ($v > 0x7f0000000000 && $v < 0x800000000000) $note = " (ptr)";
                echo sprintf("  EG+0x%03x: %s%s\n", $off, $hex, $note);
            }
        }
    }
    fclose($f);
} else {
    $err = error_get_last();
    echo "fopen FAILED: " . ($err ? $err['message'] : 'unknown') . "\n";
}
