<?php
require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/functions.php';

session_start();

redirect_if_logged_in();

$email = '';
$errors = [];

// Create or verify CSRF token helper
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Basic CSRF check
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors['general'] = "Invalid request. Please try again.";
    } else {
        $email = sanitize_input(trim($_POST['email'] ?? ''));
        $password = $_POST['password'] ?? '';

        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = "Valid email is required.";
        }
        if (empty($password)) {
            $errors['password'] = "Password is required.";
        }

        // Simple brute-force protection (example: limit per-session attempts)
        if (!isset($_SESSION['login_attempts'])) {
            $_SESSION['login_attempts'] = 0;
            $_SESSION['first_attempt_time'] = time();
        }
        // reset attempts after 15 minutes
        if (time() - ($_SESSION['first_attempt_time'] ?? 0) > 900) {
            $_SESSION['login_attempts'] = 0;
            $_SESSION['first_attempt_time'] = time();
        }
        if ($_SESSION['login_attempts'] >= 10) {
            $errors['general'] = "Too many login attempts. Try again later.";
        }

        if (empty($errors)) {
            // Make sure $conn exists and is a mysqli connection in config.php
            if ($stmt = $conn->prepare("SELECT id, name, password FROM users WHERE email = ? LIMIT 1")) {
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows === 1) {
                    $stmt->bind_result($id, $name, $hashed_password);
                    $stmt->fetch();

                    if (password_verify($password, $hashed_password)) {
                        // regenerate session id to prevent fixation
                        session_regenerate_id(true);
                        $_SESSION['user_id'] = $id;
                        $_SESSION['user_name'] = $name;

                        // Optionally rehash password if algorithm/options improved
                        if (password_needs_rehash($hashed_password, PASSWORD_DEFAULT)) {
                            $newHash = password_hash($password, PASSWORD_DEFAULT);
                            $upd = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
                            if ($upd) {
                                $upd->bind_param("si", $newHash, $id);
                                $upd->execute();
                                $upd->close();
                            }
                        }

                        // reset attempts
                        $_SESSION['login_attempts'] = 0;

                        header("Location: index.php");
                        exit();
                    } else {
                        $_SESSION['login_attempts']++;
                        $errors['general'] = "Incorrect email or password.";
                    }
                } else {
                    $_SESSION['login_attempts']++;
                    $errors['general'] = "Incorrect email or password.";
                }
                $stmt->close();
            } else {
                // Log the error for debugging, but show a generic message to the user
                error_log("DB prepare failed: " . $conn->error);
                $errors['general'] = "Unexpected error. Please try again later.";
            }
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In - TaskApp</title>
<link rel="stylesheet" href="../css/style.css">
</head>
<body>
<div class="form-container">
    <h2>Sign In</h2>
    <?php if (!empty($errors['general'])): ?>
        <div class="error"><?= htmlspecialchars($errors['general']) ?></div>
    <?php endif; ?>
    <form method="post" action="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" value="<?= htmlspecialchars($email) ?>" required>
        <small class="error"><?= htmlspecialchars($errors['email'] ?? '') ?></small>

        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
        <small class="error"><?= htmlspecialchars($errors['password'] ?? '') ?></small>

        <button type="submit">Sign In</button>
    </form>
    <p>Don't have an account? <a href="signup.php">Sign Up</a></p>
</div>
</body>
</html>
