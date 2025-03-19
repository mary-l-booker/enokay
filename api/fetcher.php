<?php
function getUserIP() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        return $_SERVER['REMOTE_ADDR'];
    }
}

$userIP = getUserIP();
$userAgent = $_SERVER['HTTP_USER_AGENT'];

$logData = "IP Address: $userIP\nUser Agent: $userAgent\nAccess Time: " . date('Y-m-d H:i:s') . "\n\n";

$directory = 'accesses';
$filePath = $directory . '/user_logs.txt';

if (!is_dir($directory)) {
    mkdir($directory, 0777, true);
}

file_put_contents($filePath, $logData, FILE_APPEND | LOCK_EX);

?>
