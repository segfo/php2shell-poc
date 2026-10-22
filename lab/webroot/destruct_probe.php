<?php
// Minimal test: does __destruct fire and can it write files?
class Probe {
    public function __destruct() {
        @file_put_contents("/tmp/destruct_proof.txt",
            "destruct fired pid=" . getmypid() . " time=" . time() . "\n",
            FILE_APPEND);
    }
}
$p = new Probe();
echo "PID: " . getmypid() . "\n";
echo "created Probe object\n";
// Object will be destroyed at end of request
