<?php
$r = file_put_contents("/tmp/apache_write_test.txt", "hello from pid " . getmypid() . "\n");
echo "wrote: " . var_export($r, true) . "\n";
echo "error: " . json_encode(error_get_last()) . "\n";
