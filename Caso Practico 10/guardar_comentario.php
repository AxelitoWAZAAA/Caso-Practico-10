<?php
// guardar_comentario.php — Caso 2: XSS corregido (sanitización en entrada + escape en salida)
declare(strict_types=1);
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/logger.php';

function guardarComentario(int $usuarioId, string $comentario): bool
{
    // 1) Validar longitud
    $comentario = trim($comentario);
    if ($comentario === '' || mb_strlen($comentario) > 500) {
        return false;
    }

    // 2) Eliminar cualquier etiqueta HTML/script antes de persistir
    $comentarioLimpio = strip_tags($comentario);

    $pdo = getDbConnection();
    $stmt = $pdo->prepare(
        'INSERT INTO comentarios (usuario_id, contenido, creado_en) VALUES (:uid, :contenido, NOW())'
    );
    $stmt->execute(['uid' => $usuarioId, 'contenido' => $comentarioLimpio]);

    logSecurityEvent('COMENTARIO_CREADO', 'Comentario registrado', (string) $usuarioId);
    return true;
}

// mostrar_comentarios.php — SIEMPRE escapar al momento de mostrar (defensa en profundidad)
function renderComentario(string $texto): string
{
    return htmlspecialchars($texto, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// Uso en la vista:
// <p><?= renderComentario($fila['contenido']) ?></p>
