<?php
// perfil.php — Caso 3: Broken Access Control (IDOR) corregido
declare(strict_types=1);
require_once __DIR__ . '/session_config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/logger.php';

if (!isset($_SESSION['usuario_id'])) {
    header('Location: /login.php');
    exit;
}

$usuarioIdSesion = (int) $_SESSION['usuario_id'];

// Se ignora cualquier "id" que venga por GET/POST para datos propios.
// El perfil que se muestra es SIEMPRE el del usuario autenticado.
$pdo = getDbConnection();
$stmt = $pdo->prepare('SELECT id, nombre, correo, direccion FROM clientes WHERE id = :id');
$stmt->execute(['id' => $usuarioIdSesion]);
$perfil = $stmt->fetch();

if (!$perfil) {
    http_response_code(404);
    exit('Perfil no encontrado.');
}

// Si existiera un panel donde un admin SÍ necesita ver otros perfiles:
function puedeVerPerfilDeOtro(int $usuarioSesionId, int $idSolicitado, PDO $pdo): bool
{
    if ($usuarioSesionId === $idSolicitado) {
        return true;
    }
    $stmt = $pdo->prepare('SELECT rol FROM usuarios WHERE id = :id');
    $stmt->execute(['id' => $usuarioSesionId]);
    $rol = $stmt->fetchColumn();
    return $rol === 'admin'; // control de acceso explícito, verificado en servidor
}
