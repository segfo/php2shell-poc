<?php
$f = "/tmp/rce_proof.txt";
echo file_exists($f) ? "RCE PROOF: " . file_get_contents($f) : "NOT FOUND";
echo "\n";
