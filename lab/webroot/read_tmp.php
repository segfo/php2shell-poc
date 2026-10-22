<?php
echo "pid: " . getmypid() . "\n";
echo "tmp contents:\n";
$files = glob("/tmp/*");
foreach ($files as $f) {
    echo "  $f (" . filesize($f) . " bytes)\n";
}
$test = "/tmp/apache_write_test.txt";
if (file_exists($test)) {
    echo "FOUND: " . file_get_contents($test);
} else {
    echo "NOT FOUND: $test\n";
}
