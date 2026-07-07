<?php
// upload_imagen.php — Caso 5: Carga de archivos con validación real
declare(strict_types=1);
require_once __DIR__ . '/logger.php';

function subirImagen(array $archivo, int $usuarioId): array
{
    $EXTENSIONES_PERMITIDAS = ['jpg', 'jpeg', 'png', 'webp'];
    $MIME_PERMITIDOS = ['image/jpeg', 'image/png', 'image/webp'];
    $MAX_BYTES = 3 * 1024 * 1024; // 3 MB

    if ($archivo['error'] !== UPLOAD_ERR_OK) {
        return ['ok' => false, 'msg' => 'Error al subir el archivo.'];
    }

    if ($archivo['size'] > $MAX_BYTES) {
        return ['ok' => false, 'msg' => 'El archivo excede el tamaño máximo permitido.'];
    }

    $extension = strtolower(pathinfo($archivo['name'], PATHINFO_EXTENSION));
    if (!in_array($extension, $EXTENSIONES_PERMITIDAS, true)) {
        logSecurityEvent('UPLOAD_REJECTED', "Extensión no permitida: $extension", (string) $usuarioId);
        return ['ok' => false, 'msg' => 'Tipo de archivo no permitido.'];
    }

    // Validar el tipo MIME real del contenido (no confiar en la extensión ni en $_FILES['type'])
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeReal = finfo_file($finfo, $archivo['tmp_name']);
    finfo_close($finfo);

    if (!in_array($mimeReal, $MIME_PERMITIDOS, true)) {
        logSecurityEvent('UPLOAD_REJECTED', "MIME real no permitido: $mimeReal", (string) $usuarioId);
        return ['ok' => false, 'msg' => 'El contenido del archivo no es una imagen válida.'];
    }

    // Nombre de archivo generado por el servidor (evita path traversal y ejecución de .php)
    $nombreSeguro = bin2hex(random_bytes(16)) . '.' . $extension;

    // Carpeta fuera del alcance de ejecución de PHP (o con .htaccess que deniegue ejecución)
    $destino = __DIR__ . '/uploads_privados/' . $nombreSeguro;

    if (!is_dir(__DIR__ . '/uploads_privados')) {
        mkdir(__DIR__ . '/uploads_privados', 0750, true);
    }

    if (!move_uploaded_file($archivo['tmp_name'], $destino)) {
        return ['ok' => false, 'msg' => 'No se pudo guardar el archivo.'];
    }

    logSecurityEvent('UPLOAD_OK', "Archivo guardado como $nombreSeguro", (string) $usuarioId);
    return ['ok' => true, 'archivo' => $nombreSeguro];
}
