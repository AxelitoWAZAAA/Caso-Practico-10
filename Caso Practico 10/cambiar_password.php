<?php
declare(strict_types=1);
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/logger.php';

function cambiarPassword(int $usuarioId, string $passwordNueva, PDO $pdo): void
{
    $hash = password_hash($passwordNueva, PASSWORD_BCRYPT, ['cost' => 12]);
    $pdo->prepare('UPDATE usuarios SET password_hash = :h WHERE id = :id')
        ->execute(['h' => $hash, 'id' => $usuarioId]);

    logSecurityEvent('PASSWORD_CHANGE', 'Contraseña actualizada', (string) $usuarioId);
}
