<?php
// auto_prepend_file: runs BEFORE the main script, during RINIT
// If OOM fires in sapi_activate() (rfc1867 parsing), this won't execute
// If OOM fires AFTER RINIT, this WILL have run

$prepend_pid = getmypid();
$prepend_time = microtime(true);

@file_put_contents('/tmp/chain_d_prepend.log',
    date('H:i:s') . " PREPEND_START pid=$prepend_pid\n", FILE_APPEND);

register_shutdown_function(function() use ($prepend_pid, $prepend_time) {
    $now_pid = getmypid();
    $err = error_get_last();
    $elapsed = microtime(true) - $prepend_time;
    $msg = date('H:i:s') . " SHUTDOWN_FROM_PREPEND pid=$now_pid "
         . "prepend_pid=$prepend_pid elapsed=" . round($elapsed, 4) . "s";
    if ($err) {
        $msg .= " error_type={$err['type']}"
              . " error_file=" . basename($err['file'] ?? 'unknown')
              . " error_line={$err['line']}"
              . " error_msg=" . substr($err['message'] ?? '', 0, 300);
    }
    $msg .= "\n";
    @file_put_contents('/tmp/chain_d_shutdown_prepend.log', $msg, FILE_APPEND);
});
