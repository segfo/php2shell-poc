<?php
echo "upload_progress.cleanup = " . var_export(ini_get("session.upload_progress.cleanup"), true) . "\n";
echo "lazy_write = " . var_export(ini_get("session.lazy_write"), true) . "\n";
echo "upload_progress.enabled = " . var_export(ini_get("session.upload_progress.enabled"), true) . "\n";
echo "save_path = " . ini_get("session.save_path") . "\n";
echo "use_only_cookies = " . ini_get("session.use_only_cookies") . "\n";

// Check if our ini file is loaded
$loaded = php_ini_loaded_file();
$scanned = php_ini_scanned_files();
echo "loaded_ini: $loaded\n";
echo "scanned_ini: $scanned\n";
