<?php
declare(strict_types=1);

function logSecurityEvent(string $type, string $message, ?string $user = null): void
{
    $logDir = __DIR__ . '/logs';
    if (!is_dir($logDir)) {
        mkdir($logDir, 0750, true);
    }

    $entry = sprintf(
        "[%s] TYPE=%s USER=%s IP=%s MSG=%s\n",
        date('Y-m-d H:i:s'),
        $type,
        $user ?? 'anonimo',
        $_SERVER['REMOTE_ADDR'] ?? 'desconocida',
        $message
    );

    file_put_contents($logDir . '/security.log', $entry, FILE_APPEND | LOCK_EX);
}
