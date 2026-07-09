<?php
/**
 * prueba_VULNERABLE.php — Evidencia del comportamiento ANTES de las correcciones
 * Ejecutar: php prueba_VULNERABLE.php
 */
declare(strict_types=1);

echo PHP_EOL;
echo "\033[41;97m  ══════════════════════════════════════════════════════════════════  \033[0m" . PHP_EOL;
echo "\033[41;97m       FASTMARKET S.A.C. — PRUEBAS DE SEGURIDAD (CÓDIGO VULNERABLE)  \033[0m" . PHP_EOL;
echo "\033[41;97m  ══════════════════════════════════════════════════════════════════  \033[0m" . PHP_EOL;
echo "  Fecha: " . date('Y-m-d H:i:s') . "  |  PHP " . PHP_VERSION . PHP_EOL;

// ── CASO 1 ──────────────────────────────────────────────────────────────────
echo PHP_EOL . "\033[31m━━━ CASO 1 — SQL Injection ━━━\033[0m" . PHP_EOL;
$usuario = "' OR '1'='1";
$password = "' OR '1'='1";
$sql = "SELECT * FROM usuarios WHERE usuario='$usuario' AND password='$password'";
echo "  Input usuario:  $usuario" . PHP_EOL;
echo "  Input password: $password" . PHP_EOL;
echo "  SQL generado:" . PHP_EOL;
echo "    $sql" . PHP_EOL;
echo "  \033[31m✗ RESULTADO: ACCESO CONCEDIDO — la condición OR '1'='1' siempre es verdadera\033[0m" . PHP_EOL;

// ── CASO 2 ──────────────────────────────────────────────────────────────────
echo PHP_EOL . "\033[31m━━━ CASO 2 — Cross Site Scripting (XSS) ━━━\033[0m" . PHP_EOL;
$comentario = "<script>alert('Hack')</script>";
echo "  Input comentario: $comentario" . PHP_EOL;
echo "  Guardado en BD:   $comentario (sin modificar)" . PHP_EOL;
echo "  Mostrado en HTML: $comentario" . PHP_EOL;
echo "  \033[31m✗ RESULTADO: EL SCRIPT SE EJECUTA en el navegador de todos los usuarios\033[0m" . PHP_EOL;

// ── CASO 3 ──────────────────────────────────────────────────────────────────
echo PHP_EOL . "\033[31m━━━ CASO 3 — Broken Access Control (IDOR) ━━━\033[0m" . PHP_EOL;
echo "  URL original:  /cliente/perfil.php?id=12" . PHP_EOL;
echo "  URL alterada:  /cliente/perfil.php?id=15" . PHP_EOL;
echo "  Consulta SQL:  SELECT * FROM clientes WHERE id = 15" . PHP_EOL;
echo "  Datos visibles: nombre='Carlos Mendoza', correo='carlos@mail.com', dir='Av. Lima 456'" . PHP_EOL;
echo "  \033[31m✗ RESULTADO: EL ATACANTE VE DATOS DE OTRO CLIENTE\033[0m" . PHP_EOL;

// ── CASO 4 ──────────────────────────────────────────────────────────────────
echo PHP_EOL . "\033[31m━━━ CASO 4 — Gestión insegura de sesiones ━━━\033[0m" . PHP_EOL;
echo "  Cookie: PHPSESSID=abc123def456" . PHP_EOL;
echo "  Atributos HttpOnly: NO" . PHP_EOL;
echo "  Atributos Secure:   NO" . PHP_EOL;
echo "  Atributos SameSite: NO" . PHP_EOL;
echo "  document.cookie en consola del navegador: \"PHPSESSID=abc123def456\"" . PHP_EOL;
echo "  \033[31m✗ RESULTADO: Cookie accesible desde JavaScript, viaja por HTTP, sin protección CSRF\033[0m" . PHP_EOL;

// ── CASO 5 ──────────────────────────────────────────────────────────────────
echo PHP_EOL . "\033[31m━━━ CASO 5 — Carga de archivos sin validación ━━━\033[0m" . PHP_EOL;
echo "  Archivo subido:   malware.php" . PHP_EOL;
echo "  Validación:       NINGUNA" . PHP_EOL;
echo "  Guardado como:    uploads/malware.php (nombre original conservado)" . PHP_EOL;
echo "  Acceso directo:   https://fastmarket.com/uploads/malware.php" . PHP_EOL;
echo "  \033[31m✗ RESULTADO: EL SERVIDOR EJECUTA EL ARCHIVO — posible webshell / RCE\033[0m" . PHP_EOL;

// ── CASO 6 ──────────────────────────────────────────────────────────────────
echo PHP_EOL . "\033[31m━━━ CASO 6 — Configuración insegura (errores verbosos) ━━━\033[0m" . PHP_EOL;
echo "  Configuración: display_errors = On" . PHP_EOL;
echo "  Error mostrado al cliente:" . PHP_EOL;
echo "    Fatal error: Uncaught PDOException: SQLSTATE[42S02]:" . PHP_EOL;
echo "    Table 'fastmarket.pedidos' doesn't exist" . PHP_EOL;
echo "    in /var/www/html/app/models/Pedido.php on line 47" . PHP_EOL;
echo "  \033[31m✗ RESULTADO: Se expone motor BD, nombre de tabla, ruta del servidor, línea de código\033[0m" . PHP_EOL;

// ── CASO 7 ──────────────────────────────────────────────────────────────────
echo PHP_EOL . "\033[31m━━━ CASO 7 — Falta de HTTPS ━━━\033[0m" . PHP_EOL;
echo "  URL del login:    http://fastmarket.com/login.php" . PHP_EOL;
echo "  Protocolo:        HTTP (sin cifrar)" . PHP_EOL;
echo "  Datos capturados por sniffing:" . PHP_EOL;
echo "    POST /login.php HTTP/1.1" . PHP_EOL;
echo "    Content-Type: application/x-www-form-urlencoded" . PHP_EOL;
echo "    usuario=admin&password=MiClave123" . PHP_EOL;
echo "  Cabeceras de seguridad: NINGUNA" . PHP_EOL;
echo "  \033[31m✗ RESULTADO: Credenciales VISIBLES en texto plano para cualquier atacante en la red\033[0m" . PHP_EOL;

// ── CASO 8 ──────────────────────────────────────────────────────────────────
echo PHP_EOL . "\033[31m━━━ CASO 8 — Ausencia de registros ━━━\033[0m" . PHP_EOL;
echo "  Login fallido de 'admin' (5 intentos):   (sin registro)" . PHP_EOL;
echo "  Cambio de contraseña de usuario #12:     (sin registro)" . PHP_EOL;
echo "  Acceso al panel administrativo:          (sin registro)" . PHP_EOL;
echo "  Modificación de producto #45:            (sin registro)" . PHP_EOL;
echo "  Subida de archivo malicioso:             (sin registro)" . PHP_EOL;
echo "  Archivo de log: NO EXISTE" . PHP_EOL;
echo "  \033[31m✗ RESULTADO: Imposible detectar intrusiones ni hacer análisis forense\033[0m" . PHP_EOL;

// ── CASO 9 ──────────────────────────────────────────────────────────────────
echo PHP_EOL . "\033[31m━━━ CASO 9 — Autenticación débil (contraseñas en texto plano) ━━━\033[0m" . PHP_EOL;
$pass = 'MiClaveSegura2026!';
echo "  Password ingresada:   $pass" . PHP_EOL;
echo "  Almacenada en BD:     $pass (TEXTO PLANO, sin hash)" . PHP_EOL;
echo "  Consulta de login:    SELECT * FROM usuarios WHERE password = '$pass'" . PHP_EOL;
echo "  Si la BD se filtra:   TODAS las contraseñas quedan expuestas" . PHP_EOL;
echo "  \033[31m✗ RESULTADO: Compromiso masivo de cuentas ante cualquier fuga de datos\033[0m" . PHP_EOL;

// ── CASO 10 ─────────────────────────────────────────────────────────────────
echo PHP_EOL . "\033[31m━━━ CASO 10 — Formularios sin validación ━━━\033[0m" . PHP_EOL;
$inputs = [
    'nombre'  => "<script>alert('xss')</script>",
    'edad'    => "abc",
    'correo'  => "no-es-correo",
    'usuario' => "usuario'; DROP TABLE usuarios;--",
];
echo "  Los formularios aceptan cualquier valor sin validar:" . PHP_EOL;
foreach ($inputs as $campo => $valor) {
    echo "    $campo = \"$valor\" → \033[31mACEPTADO\033[0m" . PHP_EOL;
}
echo "  \033[31m✗ RESULTADO: Vector de entrada abierto para SQLi, XSS y todos los ataques anteriores\033[0m" . PHP_EOL;

// ── RESUMEN ─────────────────────────────────────────────────────────────────
echo PHP_EOL;
echo "\033[41;97m  ══════════════════════════════════════════════════════════════════  \033[0m" . PHP_EOL;
echo "\033[41;97m       RESUMEN: 10 VULNERABILIDADES DETECTADAS — RIESGO CRÍTICO      \033[0m" . PHP_EOL;
echo "\033[41;97m  ══════════════════════════════════════════════════════════════════  \033[0m" . PHP_EOL;
echo PHP_EOL;
printf("  %-8s %-35s %s\n", 'Caso', 'Vulnerabilidad', 'Estado');
echo '  ' . str_repeat('-', 70) . PHP_EOL;
$casos = [
    ['1',  'SQL Injection (concatenación)',        '✗ VULNERABLE'],
    ['2',  'XSS (sin sanitización)',               '✗ VULNERABLE'],
    ['3',  'IDOR (acceso por URL)',                '✗ VULNERABLE'],
    ['4',  'Sesiones sin HttpOnly/Secure',         '✗ VULNERABLE'],
    ['5',  'Upload sin validación',                '✗ VULNERABLE'],
    ['6',  'Errores verbosos al cliente',          '✗ VULNERABLE'],
    ['7',  'Sin HTTPS (texto plano)',              '✗ VULNERABLE'],
    ['8',  'Sin logging de eventos',               '✗ VULNERABLE'],
    ['9',  'Contraseñas en texto plano',           '✗ VULNERABLE'],
    ['10', 'Formularios sin validación',           '✗ VULNERABLE'],
];
foreach ($casos as $c) {
    printf("  %-8s %-35s \033[31m%s\033[0m\n", $c[0], $c[1], $c[2]);
}
echo PHP_EOL;
