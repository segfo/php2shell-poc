<?php
header("Content-Type: text/plain");
echo "PID: " . getmypid() . "\n";

// Create some objects to populate objects_store
$obj1 = new stdClass();
$obj2 = new stdClass();
$obj3 = new ArrayObject([1,2,3]);

echo "Created 3 objects\n";

// Write PID to a file so external process can read memory
file_put_contents("/tmp/probe_pid", (string)getmypid());

// Signal that we're ready and wait
file_put_contents("/tmp/probe_ready", "1");
echo "Waiting for signal...\n";
flush();

// Wait up to 10 seconds for the dump to complete
for ($i = 0; $i < 100; $i++) {
    if (file_exists("/tmp/probe_done")) {
        break;
    }
    usleep(100000); // 100ms
}

@unlink("/tmp/probe_ready");
@unlink("/tmp/probe_done");
@unlink("/tmp/probe_pid");

echo "Done. Objects still alive: " . (isset($obj1) ? "yes" : "no") . "\n";
