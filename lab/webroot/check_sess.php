<?php
$sid = $_GET["sid"] ?? "";
if (!$sid) { echo "need ?sid=xxx"; exit; }
$sp = session_save_path() ?: "/tmp";
$path = "$sp/sess_$sid";
if (file_exists($path)) {
    $c = file_get_contents($path);
    echo "SIZE: " . strlen($c) . "\n";
    echo "CONTENT: " . $c . "\n";
    echo "FORMAT: " . (substr($c, 0, 2) === "a:" ? "php_serialize" : (strpos($c, "|") !== false ? "php" : "unknown")) . "\n";
} else {
    echo "NOT FOUND\n";
}
