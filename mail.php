<?php
require 'vendor/autoload.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Load environment variables
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
    $dotenv->load();

    // DB credentials
    $servername = $_ENV['DB_HOST'];
    $username   = $_ENV['DB_USER'];
    $password   = $_ENV['DB_PASS'];
    $port       = $_ENV['DB_PORT'];
    $dbname     = $_ENV['DB_NAME'];

    $conn = new mysqli($servername, $username, $password, $dbname, $port);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Collect form data
    $userEmail    = $_POST['email'] ?? null;
    $userName     = $_POST['name'] ?? null;
    $userPassword = $_POST['password'] ?? null;

    if (!$userEmail || !$userPassword) {
        die("Email and password are required.");
    }

    $hashedPassword = password_hash($userPassword, PASSWORD_DEFAULT);

    if (filter_var($userEmail, FILTER_VALIDATE_EMAIL)) { 
        
        $mail = new PHPMailer(true);

        try {
            // SMTP settings
            $mail->isSMTP();
            $mail->Host       = 'smtp.gmail.com';
            $mail->SMTPAuth   = true;
            $mail->Username   = $_ENV['SMTP_USER']; // full Gmail address
            $mail->Password   = $_ENV['SMTP_PASS']; // Gmail App Password (16 chars)
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
            $mail->Port       = 465; // ✅ FIXED

            // Recipients
            $mail->setFrom('BBIT2.2@noreply.com', 'BBIT 2.2');
            $mail->addAddress($userEmail, $userName);

            // Content
            $mail->isHTML(true);
            $mail->Subject = 'Welcome to BBIT 2.2! Account Verification';
            $mail->Body    = "Hello " . htmlspecialchars($userName) . ",<br><br>" .
                             "You requested an account on BBIT 2.2.<br><br>" .
                             "In order to use this account you need to <a href='index.php'>Click Here</a> to complete the registration process.<br><br>" .
                             "Regards,<br>Systems Admin<br>ICS 2.2";

            $mail->send();

            // Save user in DB
            $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $userName, $userEmail, $hashedPassword);
            $stmt->execute();
            $stmt->close();

            header("Location: signin.php");
            exit();

        } catch (Exception $e) {
            error_log("Mailer Error: " . $mail->ErrorInfo);
            echo "Sorry, we couldn’t send the verification email. Please try again later.";
        }
        
    } else {
        echo "Invalid email address."; 
    }

    $conn->close();
}
?>
