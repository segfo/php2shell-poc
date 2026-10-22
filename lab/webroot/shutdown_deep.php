<?php
// This script investigates what php_request_shutdown() actually does after OOM
// by examining internal state via a shutdown function

// Register at script level (this runs on normal requests, not OOM ones)
register_shutdown_function(function() {
    $err = error_get_last();
    $info = [
        "pid" => getmypid(),
        "error" => $err,
        "num_objects_in_store" => 0,
    ];
    // Count objects via get_defined_vars reflection
    $gc = gc_status();
    $info["gc"] = $gc;

    // Check $_FILES state
    $info["files_count"] = count($_FILES ?? []);
    $info["post_count"] = count($_POST ?? []);

    @file_put_contents("/tmp/shutdown_deep.json",
        json_encode($info, JSON_PRETTY_PRINT) . "\n", FILE_APPEND);
});

echo "PID: " . getmypid() . "\n";
echo "OK\n";
