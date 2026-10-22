<?php
// Chain D verification: Test if OOM leaves stale EG() state on mod_php
// This script orchestrates the test sequence and reports results

$action = $_GET['action'] ?? 'status';
$logfile = "/tmp/eg_oom_test.log";

switch ($action) {
    case 'reset':
        // Clean slate
        @unlink($logfile);
        @unlink("/tmp/destruct_after_oom.log");
        echo "RESET OK\n";
        break;

    case 'populate':
        // Step 1: Create objects in EG(objects_store)
        // These objects track themselves and log when their destructor fires
        class TrackedObject {
            public static $count = 0;
            public $id;
            public $pid;
            public function __construct() {
                $this->id = ++self::$count;
                $this->pid = getmypid();
            }
            public function __destruct() {
                $msg = date("H:i:s") . " DESTRUCT TrackedObject#{$this->id} created_pid={$this->pid} destruct_pid=" . getmypid() . "\n";
                @file_put_contents("/tmp/destruct_after_oom.log", $msg, FILE_APPEND);
            }
        }

        $objects = [];
        for ($i = 0; $i < 50; $i++) {
            $objects[] = new TrackedObject();
        }

        $pid = getmypid();
        $msg = date("H:i:s") . " POPULATE pid=$pid objects=" . TrackedObject::$count . "\n";
        @file_put_contents($logfile, $msg, FILE_APPEND);

        echo "PID: $pid\n";
        echo "objects_created: " . TrackedObject::$count . "\n";
        echo "POPULATE OK\n";
        // Objects will be destroyed during RSHUTDOWN
        break;

    case 'check_post_oom':
        // Step 3: After OOM, check what state remains
        $pid = getmypid();
        $msg = date("H:i:s") . " CHECK pid=$pid\n";
        @file_put_contents($logfile, $msg, FILE_APPEND);

        echo "PID: $pid\n";
        echo "last_error: " . json_encode(error_get_last()) . "\n";
        echo "gc_status: " . json_encode(gc_status()) . "\n";
        echo "memory_usage: " . memory_get_usage(true) . "\n";
        echo "peak_memory: " . memory_get_peak_usage(true) . "\n";

        // Read logs
        echo "\n--- destruct log ---\n";
        echo @file_get_contents("/tmp/destruct_after_oom.log") ?: "(empty)\n";

        echo "\n--- test log ---\n";
        echo @file_get_contents($logfile) ?: "(empty)\n";
        break;

    case 'status':
    default:
        echo "PID: " . getmypid() . "\n";
        echo "SAPI: " . php_sapi_name() . "\n";
        echo "memory_limit: " . ini_get('memory_limit') . "\n";
        echo "Actions: ?action=reset|populate|check_post_oom\n";
        break;
}
