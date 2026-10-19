<?php
$conn = mysqli_connect("db", "app", getenv("DB_PASSWORD"), "app");
// rempart-expect: CODE-XSS-SINK
echo "Results for " . $_GET['q'];
// rempart-safe: CODE-XSS-SINK
echo "Results for " . htmlspecialchars($_GET['q'], ENT_QUOTES);
// rempart-expect: CODE-SQL-INJECTION
$res = mysqli_query($conn, "SELECT * FROM items WHERE name = '" . $_GET['q'] . "'");
$stmt = $conn->prepare("SELECT * FROM items WHERE name = ?");
// rempart-expect: CODE-CMD-INJECTION
system("ping -c 1 " . $_GET['host']);
