<?php
// Test: does OOM bypass session.upload_progress.cleanup?
// Check if session files injected via upload_progress survive when cleanup=On

$action = $_GET['action'] ?? 'status';
$sid = $_GET['sid'] ?? '';
$sp = ini_get('session.save_path') ?: '/tmp';

switch ($action) {
    case 'check_cleanup_setting':
        echo "cleanup: " . ini_get('session.upload_progress.cleanup') . "\n";
        echo "enabled: " . ini_get('session.upload_progress.enabled') . "\n";
        echo "lazy_write: " . ini_get('session.lazy_write') . "\n";
        echo "save_path: $sp\n";
        echo "PID: " . getmypid() . "\n";
        break;

    case 'check_session':
        if (!$sid) { echo "need ?sid=xxx\n"; exit; }
        $path = "$sp/sess_$sid";
        if (file_exists($path)) {
            $c = file_get_contents($path);
            echo "EXISTS: yes\n";
            echo "SIZE: " . strlen($c) . "\n";
            echo "CONTENT: $c\n";
        } else {
            echo "EXISTS: no\n";
            echo "PATH: $path\n";
        }
        break;

    case 'list_sessions':
        $files = glob("$sp/sess_*");
        echo "count: " . count($files) . "\n";
        foreach (array_slice($files, -10) as $f) {
            echo basename($f) . " (" . filesize($f) . " bytes)\n";
        }
        break;

    case 'status':
    default:
        echo "PID: " . getmypid() . "\n";
        echo "Actions: ?action=check_cleanup_setting|check_session&sid=X|list_sessions\n";
        break;
}
