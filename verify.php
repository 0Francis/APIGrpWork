<?php
session_start();
require "db.php";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $userOtp = $_POST["otp"] ?? "";

    if ($userOtp == $_SESSION['otp']) {
        $email = $_SESSION['email'];

        // Save email to DB
        $stmt = $conn->prepare("INSERT INTO users (email) VALUES (?)");
        $stmt->bind_param("s", $email);
        $stmt->execute();

        echo "Signup successful for " . $email;

        // Clear session
        unset($_SESSION['otp']);
        unset($_SESSION['email']);
    } else {
        echo "Invalid OTP.";
    }
}
?>
