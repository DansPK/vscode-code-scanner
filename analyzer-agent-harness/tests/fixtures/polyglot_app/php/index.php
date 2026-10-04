<?php
$conn = mysqli_connect("localhost", "u", "p", "app");
$name = $_GET["name"];
mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");
system("ping -c 1 " . $_GET["host"]);
echo $_GET["msg"];
