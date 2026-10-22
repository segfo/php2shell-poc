<?php
$action = $_GET['action'] ?? 'info';
$logfile = '/tmp/chain_d_verify.log';

switch ($action) {

case 'reset':
    @unlink($logfile);
    @unlink('/tmp/chain_d_destruct.log');
    @unlink('/tmp/chain_d_shutdown.log');
    echo "RESET OK\n";
    break;

case 'populate':
    // Create objects tracked in EG(objects_store)
    // Their destructor logs when/where it fires
    class TrackedObj {
        public $id;
        public $create_pid;
        public function __construct($id) {
            $this->id = $id;
            $this->create_pid = getmypid();
        }
        public function __destruct() {
            $pid = getmypid();
            $msg = date('H:i:s') . " DESTRUCT id=$this->id create_pid=$this->create_pid destruct_pid=$pid\n";
            @file_put_contents('/tmp/chain_d_destruct.log', $msg, FILE_APPEND);
        }
    }

    // Register a shutdown function to detect if it fires after OOM
    register_shutdown_function(function() {
        $pid = getmypid();
        $err = error_get_last();
        $msg = date('H:i:s') . " SHUTDOWN pid=$pid";
        if ($err) {
            $msg .= " error_type={$err['type']} error_msg=" . substr($err['message'], 0, 200);
        }
        $msg .= "\n";
        @file_put_contents('/tmp/chain_d_shutdown.log', $msg, FILE_APPEND);
    });

    $objects = [];
    for ($i = 0; $i < 100; $i++) {
        $objects[] = new TrackedObj($i);
    }

    $pid = getmypid();
    @file_put_contents($logfile, date('H:i:s') . " POPULATE pid=$pid objects=100\n", FILE_APPEND);

    echo "PID: $pid\n";
    echo "SAPI: " . php_sapi_name() . "\n";
    echo "objects_created: 100\n";
    echo "memory_usage: " . memory_get_usage(true) . "\n";
    echo "POPULATE OK\n";
    break;

case 'probe':
    // After OOM: check PID, EG state, and logs
    $pid = getmypid();
    $gc = gc_status();

    echo "PID: $pid\n";
    echo "SAPI: " . php_sapi_name() . "\n";
    echo "gc_roots: {$gc['roots']}\n";
    echo "gc_runs: {$gc['runs']}\n";
    echo "gc_collected: {$gc['collected']}\n";
    echo "memory_usage: " . memory_get_usage(true) . "\n";
    echo "peak_memory: " . memory_get_peak_usage(true) . "\n";
    echo "last_error: " . json_encode(error_get_last()) . "\n";

    echo "\n--- destruct log ---\n";
    if (file_exists('/tmp/chain_d_destruct.log')) {
        echo file_get_contents('/tmp/chain_d_destruct.log');
    } else {
        echo "(empty)\n";
    }

    echo "\n--- shutdown log ---\n";
    if (file_exists('/tmp/chain_d_shutdown.log')) {
        echo file_get_contents('/tmp/chain_d_shutdown.log');
    } else {
        echo "(empty)\n";
    }

    echo "\n--- verify log ---\n";
    if (file_exists($logfile)) {
        echo file_get_contents($logfile);
    } else {
        echo "(empty)\n";
    }
    break;

case 'info':
default:
    $pid = getmypid();
    echo "PID: $pid\n";
    echo "SAPI: " . php_sapi_name() . "\n";
    echo "memory_limit: " . ini_get('memory_limit') . "\n";
    echo "post_max_size: " . ini_get('post_max_size') . "\n";
    echo "upload_max_filesize: " . ini_get('upload_max_filesize') . "\n";
    echo "max_file_uploads: " . ini_get('max_file_uploads') . "\n";
    echo "max_input_vars: " . ini_get('max_input_vars') . "\n";
    echo "session.upload_progress.enabled: " . ini_get('session.upload_progress.enabled') . "\n";
    echo "OK\n";
    break;
}
