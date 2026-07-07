<?php
// error_handler.php — Caso 6: Manejo centralizado de errores
declare(strict_types=1);
require_once __DIR__ . '/logger.php';

ini_set('display_errors', '0');   // nunca mostrar errores al cliente
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/logs/php_errors.log');

set_exception_handler(function (Throwable $e): void {
    logSecurityEvent('ERROR', 'Excepción no controlada: ' . $e->getMessage());
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Ocurrió un error interno. Intente más tarde.']);
    exit;
});

set_error_handler(function (int $severity, string $message, string $file, int $line): bool {
    logSecurityEvent('PHP_ERROR', "$message en $file:$line");
    return true; // evita que PHP imprima el error nativo
});
