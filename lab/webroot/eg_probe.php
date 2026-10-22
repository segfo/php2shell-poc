<?php
// EG() state probe - checks if stale state persists across requests
// Reports: PID, objects in EG(objects_store), registered shutdown functions

$pid = getmypid();
$sapi = php_sapi_name();

// Create an object that will be tracked in EG(objects_store)
class Marker {
    public $id;
    public $created_at;
    public function __construct($id) {
        $this->id = $id;
        $this->created_at = microtime(true);
    }
    public function __destruct() {
        $p = getmypid();
        file_put_contents("/tmp/eg_destruct.log",
            date("H:i:s") . " PID=$p Marker#$this->id destructed\n",
            FILE_APPEND);
    }
}

// Create markers that populate EG(objects_store)
$markers = [];
for ($i = 0; $i < 10; $i++) {
    $markers[] = new Marker($i);
}

echo "PID: $pid\n";
echo "SAPI: $sapi\n";
echo "objects_created: 10\n";
echo "memory_usage: " . memory_get_usage(true) . "\n";
echo "memory_limit: " . ini_get('memory_limit') . "\n";
echo "OK\n";
