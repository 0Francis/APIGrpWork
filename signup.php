<?php
session_start();
require __DIR__ . '/vendor/autoload.php'; 
require "db.php";

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST["email"] ?? "";

    if (empty($email)) {
        echo "Email is required.";
        exit;
    }

    // Check if user already exists
    $check = $conn->prepare("SELECT * FROM users WHERE email=?");
    $check->bind_param("s", $email);
    $check->execute();
    $result = $check->get_result();

    if ($result->num_rows > 0) {
        echo "Email already registered.";
        exit;
    }

    // Generate OTP
    $otp = rand(100000, 999999);
    $_SESSION['otp']   = $otp;
    $_SESSION['email'] = $email;

    // Send OTP via PHPMailer
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'yourgmail@gmail.com';   // your Gmail
        $mail->Password   = 'your-app-password';     // Gmail app password
        $mail->SMTPSecure = 'tls';
        $mail->Port       = 587;

        $mail->setFrom('yourgmail@gmail.com', 'Your App');
        $mail->addAddress($email);
        $mail->Subject = "Your OTP Code";
        $mail->Body    = "Your OTP is: $otp";

        $mail->send();
        echo "OTP sent to $email. Please verify.";
    } catch (Exception $e) {
        echo "Mailer Error: {$mail->ErrorInfo}";
    }
}
?>
