<?php
// registro.php — Caso 9: Autenticación fuerte (bcrypt hash en registro)
declare(strict_types=1);
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/logger.php';

function registrarUsuario(string $usuario, string $correo, string $passwordPlano): array
{
    if (strlen($passwordPlano) < 10) {
        return ['ok' => false, 'msg' => 'La contraseña debe tener al menos 10 caracteres.'];
    }
    if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
        return ['ok' => false, 'msg' => 'Correo no válido.'];
    }

    $hash = password_hash($passwordPlano, PASSWORD_BCRYPT, ['cost' => 12]);

    $pdo = getDbConnection();
    $stmt = $pdo->prepare(
        'INSERT INTO usuarios (usuario, correo, password_hash, intentos_fallidos)
         VALUES (:usuario, :correo, :hash, 0)'
    );
    $stmt->execute(['usuario' => $usuario, 'correo' => $correo, 'hash' => $hash]);

    logSecurityEvent('REGISTRO_OK', 'Usuario registrado', $usuario);
    return ['ok' => true];
}
