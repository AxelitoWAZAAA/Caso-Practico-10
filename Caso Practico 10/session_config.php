<?php
declare(strict_types=1);

session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);

ini_set('session.use_strict_mode', '1');
session_name('FM_SESSID');
session_start();

function regenerateSession(): void
{
    session_regenerate_id(true);
}
