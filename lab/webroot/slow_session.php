<?php
session_id("slowsess000000000000000000");
session_start();
$_SESSION["active"] = true;
sleep(5);
echo "DONE";
