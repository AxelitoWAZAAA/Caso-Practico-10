<?php
// login.php — Caso 1: SQL Injection corregido (PDO + prepared statement + verificación de hash)
declare(strict_types=1);
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/logger.php';

function login(string $usuario, string $passwordPlano): array|false
{
    $pdo = getDbConnection();

    $stmt = $pdo->prepare(
        'SELECT id, usuario, password_hash, intentos_fallidos, bloqueado_hasta
         FROM usuarios WHERE usuario = :usuario LIMIT 1'
    );
    $stmt->execute(['usuario' => $usuario]);
    $user = $stmt->fetch();

    if (!$user) {
        logSecurityEvent('LOGIN_FAIL', 'Usuario no existe', $usuario);
        return false;
    }

    if ($user['bloqueado_hasta'] !== null && strtotime($user['bloqueado_hasta']) > time()) {
        logSecurityEvent('LOGIN_BLOCKED', 'Cuenta bloqueada temporalmente', $usuario);
        return false;
    }

    if (!password_verify($passwordPlano, $user['password_hash'])) {
        $intentos = $user['intentos_fallidos'] + 1;
        $bloqueo = $intentos >= 5
            ? date('Y-m-d H:i:s', strtotime('+15 minutes'))
            : null;

        $upd = $pdo->prepare(
            'UPDATE usuarios SET intentos_fallidos = :i, bloqueado_hasta = :b WHERE id = :id'
        );
        $upd->execute(['i' => $intentos, 'b' => $bloqueo, 'id' => $user['id']]);

        logSecurityEvent('LOGIN_FAIL', "Password incorrecta (intento $intentos)", $usuario);
        return false;
    }

    // Login correcto: resetear contador de intentos
    $pdo->prepare('UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = :id')
        ->execute(['id' => $user['id']]);

    logSecurityEvent('LOGIN_OK', 'Autenticación exitosa', $usuario);
    return $user;
}
