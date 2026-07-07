<?php
// session_config.php — Caso 4: Sesiones seguras
declare(strict_types=1);

session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => true,      // solo se envía por HTTPS
    'httponly' => true,      // no accesible desde JavaScript
    'samesite' => 'Strict',  // mitiga CSRF
]);

ini_set('session.use_strict_mode', '1');
session_name('FM_SESSID'); // evita exponer que el backend es PHP por defecto
session_start();

// Regenerar el ID de sesión tras login exitoso (mitiga session fixation)
function regenerateSession(): void
{
    session_regenerate_id(true);
}
