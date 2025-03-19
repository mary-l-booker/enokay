<?php

function validate_captcha_response($code) {
    if ($_SERVER['HTTP_HOST'] == "localhost") {
        return true; 
    }

    if (!$code) {
        return false;
    }

    $secret = "6Lfpi_kqAAAAAMwS-nURxF4SyM3lwiOa-uXzIi1r"; 
    $ip = $_SERVER['REMOTE_ADDR'];
    $url = "https://www.google.com/recaptcha/api/siteverify?secret=$secret&response=$code&remoteip=$ip";
    $response = file_get_contents($url);
    $gcaptcha = json_decode($response, true);

    return $gcaptcha['success'] == true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $recaptchaResponse = $_POST['recaptcha_response'];

    if (validate_captcha_response($recaptchaResponse)) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false]);
    }
}
?>