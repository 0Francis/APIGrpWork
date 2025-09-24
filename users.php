<?php
// --- Database Connection ---
require 'vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$servername = $_ENV['DB_HOST'];
$username   = $_ENV['DB_USER'];
$password   = $_ENV['DB_PASS'];
$port       = $_ENV['DbPort'];
$dbname     = $_ENV['DB_NAME'];

$conn = new mysqli($servername, $username, $password, $dbname, $port);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// SQL query to get users sorted by name (ascending)
$sql = "SELECT id, name, email, reg_date FROM app_users ORDER BY name ASC";
$result = $conn->query($sql);
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Registered Users</title>
    <style>
        body { font-family: sans-serif; padding: 20px; }
        ol { list-style-type: decimal; }
    </style>
</head>
<body>
    <h1>List of Registered Users</h1>
    <ol>
        <?php
        if ($result->num_rows > 0) {
            while($row = $result->fetch_assoc()) {
                echo "<li>" . htmlspecialchars($row["name"]) . 
                     " - " . htmlspecialchars($row["email"]) . 
                     " - Registered: " . $row["reg_date"] . "</li>";
            }
        } else {
            echo "<li>No users found.</li>";    
        }
        $conn->close();
        ?>
    </ol>
</body>
</html>