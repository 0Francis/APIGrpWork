<?php
require __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;

// Load .env
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();

// DB credentials
$servername = $_ENV['DB_HOST'];
$username   = $_ENV['DB_USER'];
$password   = $_ENV['DB_PASS'];
$port       = $_ENV['DB_PORT'];
$dbname     = $_ENV['DB_NAME'];

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname, $port);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$success = "";
$error = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? '';
    $otp   = $_POST['otp'] ?? '';

    // Clean email
    $email = filter_var($email, FILTER_SANITIZE_EMAIL);

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "❌ Invalid email address.";
    } else {
        $stmt = $conn->prepare("SELECT id, otp_hash, otp_expires, otp_attempts FROM app_users WHERE email = ? LIMIT 1");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $res = $stmt->get_result();

        if ($row = $res->fetch_assoc()) {
            // Lockout after 5 attempts
            if ($row['otp_attempts'] >= 5) {
                $error = "❌ Too many failed attempts. Please request a new code.";
            } else {
                // Check expiry
                $now = new DateTime();
                $expires = new DateTime($row['otp_expires']);

                if ($expires < $now) {
                    $error = "⏰ Code expired. Please request a new verification email.";
                } else {
                    // Verify OTP
                    if (password_verify((string)$otp, $row['otp_hash'])) {
                        // Success — mark as verified
                        $u = $conn->prepare("UPDATE app_users 
                                             SET is_verified = 1, otp_hash = NULL, otp_expires = NULL, otp_attempts = 0 
                                             WHERE id = ?");
                        $u->bind_param("i", $row['id']);
                        $u->execute();
                        $u->close();

                        $success = "✅ Your account has been verified successfully. You can now login.";
                    } else {
                        // Increment failed attempts
                        $inc = $conn->prepare("UPDATE app_users SET otp_attempts = otp_attempts + 1 WHERE id = ?");
                        $inc->bind_param("i", $row['id']);
                        $inc->execute();
                        $inc->close();

                        $error = "❌ Invalid code. Please try again.";
                    }
                }
            }
        } else {
            $error = "❌ No account found for that email.";
        }

        $stmt->close();
    }
}

$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Verify Account</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        form { max-width: 400px; padding: 20px; border: 1px solid #ccc; border-radius: 10px; }
        label { display: block; margin-top: 10px; }
        input { padding: 8px; width: 95%; margin-top: 5px; }
        button { margin-top: 15px; padding: 10px; width: 100%; background: #0073e6; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #005bb5; }
        .msg { margin: 15px 0; padding: 10px; border-radius: 5px; }
        .error { background: #ffe5e5; color: #b30000; }
        .success { background: #e6ffe6; color: #006600; }
    </style>
</head>
<body>

    <h1>Verify Your Account</h1>

    <?php if ($error): ?>
        <div class="msg error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if ($success): ?>
        <div class="msg success"><?= htmlspecialchars($success) ?></div>
    <?php endif; ?>

    <form method="post">
        <label>Email:
            <input type="email" name="email" required>
        </label>
        <label>Verification Code (6 digits):
            <input type="text" name="otp" pattern="\d{6}" maxlength="6" required>
        </label>
        <button type="submit">Verify</button>
    </form>

    <p>Didn’t receive or code expired? <a href="resend.php">Resend verification email</a></p>

</body>
</html>
