<?php
function sanitize_input($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}

function is_logged_in() {
    // session_start(); // Ensure session is started before checking but better to start session in the main files
    return isset($_SESSION['user_id']);
}

function redirect_if_logged_in() {
    if (is_logged_in()) {
        header("Location: index.php");
        exit();
    }
}

function require_login() {
    if (!is_logged_in()) {
        header("Location: signin.php");
        exit();
    }
}


?>