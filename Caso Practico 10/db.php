<?php
// db.php
declare(strict_types=1);

function getDbConnection(): PDO
{
    $host = 'localhost';
    $db   = 'fastmarket';
    $user = 'fastmarket_app'; // usuario con privilegios mínimos, NO root
    $pass = getenv('DB_PASSWORD'); // nunca hardcodear credenciales
    $charset = 'utf8mb4';

    $dsn = "mysql:host=$host;dbname=$db;charset=$charset";
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false, // fuerza prepares reales del driver
    ];

    return new PDO($dsn, $user, $pass, $options);
}
