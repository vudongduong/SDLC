<?php
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', '');
define('DB_DATABASE', 'student_atd_managament1');

$conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_DATABASE);

if ($conn === false) {
    die('ERROR: Could not connect. ' . mysqli_connect_error());
// } else {
//     echo 'Good job.';
}