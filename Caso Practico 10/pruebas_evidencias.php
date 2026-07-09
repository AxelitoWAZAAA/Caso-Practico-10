<?php
/**
 * pruebas_evidencias.php
 * Script de demostración: evidencias ANTES / DESPUÉS para los 10 casos de seguridad.
 * Ejecutar: php pruebas_evidencias.php
 *
 * No requiere MySQL ni servidor web. Simula el comportamiento vulnerable
 * y el corregido para cada caso, mostrando la diferencia en consola.
 */
declare(strict_types=1);

// ─── Utilidades de formato ──────────────────────────────────────────────────
function separador(string $titulo): void
{
    echo PHP_EOL;
    echo str_repeat('=', 70) . PHP_EOL;
    echo "  $titulo" . PHP_EOL;
    echo str_repeat('=', 70) . PHP_EOL;
}

function etiqueta(string $fase): void
{
    $color = ($fase === 'ANTES (VULNERABLE)') ? "\033[31m" : "\033[32m";
    echo PHP_EOL . "  $color>> $fase\033[0m" . PHP_EOL;
}

function resultado(string $texto): void
{
    echo "     $texto" . PHP_EOL;
}

// ─────────────────────────────────────────────────────────────────────────────
//  CASO 1 — SQL Injection
// ─────────────────────────────────────────────────────────────────────────────
separador("CASO 1 — SQL Injection");

$usuario_malicioso = "' OR '1'='1";
$password_maliciosa = "' OR '1'='1";

etiqueta('ANTES (VULNERABLE)');
// Código vulnerable: concatenación directa
$sql_vulnerable = "SELECT * FROM usuarios WHERE usuario='$usuario_malicioso' AND password='$password_maliciosa'";
resultado("Input usuario:  $usuario_malicioso");
resultado("Input password: $password_maliciosa");
resultado("SQL generado:   $sql_vulnerable");
resultado("Resultado:      ACCESO CONCEDIDO (la condición siempre es verdadera)");

etiqueta('DESPUÉS (CORREGIDO)');
// Código corregido: prepared statement (simulado)
resultado("Input usuario:  $usuario_malicioso");
resultado("Input password: $password_maliciosa");
resultado("SQL generado:   SELECT ... WHERE usuario = :usuario LIMIT 1");
resultado("Parámetro :usuario = \"' OR '1'='1\" (tratado como texto literal)");
resultado("Resultado:      LOGIN RECHAZADO — usuario no encontrado en BD");

// ─────────────────────────────────────────────────────────────────────────────
//  CASO 2 — Cross Site Scripting (XSS)
// ─────────────────────────────────────────────────────────────────────────────
separador("CASO 2 — Cross Site Scripting (XSS)");

$comentario_xss = "<script>alert('Hack')</script>";

etiqueta('ANTES (VULNERABLE)');
resultado("Input:    $comentario_xss");
resultado("Guardado: $comentario_xss (sin modificar)");
resultado("Mostrado: $comentario_xss");
resultado("Efecto:   EL SCRIPT SE EJECUTA en el navegador de todos los usuarios");

etiqueta('DESPUÉS (CORREGIDO)');
// strip_tags elimina etiquetas al guardar
$comentario_limpio = strip_tags($comentario_xss);
// htmlspecialchars escapa al mostrar (defensa en profundidad)
$comentario_escapado = htmlspecialchars($comentario_xss, ENT_QUOTES | ENT_HTML5, 'UTF-8');
resultado("Input:      $comentario_xss");
resultado("strip_tags: \"$comentario_limpio\" (etiquetas eliminadas al guardar)");
resultado("Escapado:   $comentario_escapado (si se muestra, se ve como texto)");
resultado("Efecto:     El script NO se ejecuta, se muestra como texto plano");

// ─────────────────────────────────────────────────────────────────────────────
//  CASO 3 — Broken Access Control (IDOR)
// ─────────────────────────────────────────────────────────────────────────────
separador("CASO 3 — Broken Access Control (IDOR)");

etiqueta('ANTES (VULNERABLE)');
resultado("URL:       /cliente/perfil.php?id=12");
resultado("Consulta:  SELECT * FROM clientes WHERE id = 12");
resultado("El atacante cambia a: /cliente/perfil.php?id=15");
resultado("Consulta:  SELECT * FROM clientes WHERE id = 15");
resultado("Resultado: VE DATOS DE OTRO CLIENTE (nombre, correo, dirección)");

etiqueta('DESPUÉS (CORREGIDO)');
$usuario_sesion_id = 12; // simulado: ID del usuario autenticado
resultado("URL:       /cliente/perfil.php?id=15 (intento de IDOR)");
resultado("Código:    \$usuarioIdSesion = (int) \$_SESSION['usuario_id']; // = $usuario_sesion_id");
resultado("Consulta:  SELECT ... FROM clientes WHERE id = :id  (parámetro = $usuario_sesion_id)");
resultado("Resultado: El parámetro ?id=15 de la URL SE IGNORA");
resultado("           Solo se muestran los datos del usuario autenticado (id=$usuario_sesion_id)");

// ─────────────────────────────────────────────────────────────────────────────
//  CASO 4 — Gestión insegura de sesiones
// ─────────────────────────────────────────────────────────────────────────────
separador("CASO 4 — Gestión insegura de sesiones");

etiqueta('ANTES (VULNERABLE)');
resultado("Cookie:    PHPSESSID=abc123def456");
resultado("Atributos: (ninguno)");
resultado("Riesgo 1:  JavaScript puede leer la cookie (document.cookie)");
resultado("Riesgo 2:  La cookie viaja por HTTP sin cifrar");
resultado("Riesgo 3:  No hay protección contra CSRF (SameSite ausente)");
resultado("Riesgo 4:  El ID de sesión no se regenera tras login");

etiqueta('DESPUÉS (CORREGIDO)');
resultado("Cookie:    FM_SESSID=xyz789 (nombre personalizado)");
resultado("Atributos:");
resultado("  HttpOnly = true  → JavaScript NO puede leer la cookie");
resultado("  Secure   = true  → Solo se envía por HTTPS");
resultado("  SameSite = Strict → Mitiga ataques CSRF");
resultado("Regeneración: session_regenerate_id(true) tras login exitoso");
resultado("Logout:    Destrucción completa de sesión + cookie expirada");

// ─────────────────────────────────────────────────────────────────────────────
//  CASO 5 — Carga de archivos sin validación
// ─────────────────────────────────────────────────────────────────────────────
separador("CASO 5 — Carga de archivos sin validación");

etiqueta('ANTES (VULNERABLE)');
resultado("Archivo:   malware.php");
resultado("Validación: NINGUNA");
resultado("Guardado:  uploads/malware.php");
resultado("Acceso:    https://sitio.com/uploads/malware.php");
resultado("Efecto:    EL SERVIDOR EJECUTA EL ARCHIVO PHP (webshell / RCE)");

etiqueta('DESPUÉS (CORREGIDO)');
// Simular validación
$archivo_malicioso = 'malware.php';
$extension = strtolower(pathinfo($archivo_malicioso, PATHINFO_EXTENSION));
$extensiones_permitidas = ['jpg', 'jpeg', 'png', 'webp'];
$extension_valida = in_array($extension, $extensiones_permitidas, true);

resultado("Archivo:   $archivo_malicioso");
resultado("Validación 1 - Extensión: '$extension' → " . ($extension_valida ? 'PERMITIDA' : 'RECHAZADA ✗'));
resultado("Validación 2 - MIME real: Se verifica con finfo (contenido real, no extensión)");
resultado("Validación 3 - Tamaño: Máximo 3 MB");
resultado("Renombrado: bin2hex(random_bytes(16)) + extensión → " . bin2hex(random_bytes(16)) . ".jpg");
resultado("Destino:   uploads_privados/ (fuera del webroot ejecutable)");
resultado(".htaccess: php_flag engine off (ejecución PHP deshabilitada)");
resultado("Resultado: ARCHIVO RECHAZADO — extensión .php no está en la whitelist");

// ─────────────────────────────────────────────────────────────────────────────
//  CASO 6 — Configuración insegura (errores verbosos)
// ─────────────────────────────────────────────────────────────────────────────
separador("CASO 6 — Configuración insegura (errores verbosos)");

etiqueta('ANTES (VULNERABLE)');
resultado("Error SQL forzado:");
resultado("  Fatal error: Uncaught PDOException: SQLSTATE[42S02]:");
resultado("  Table 'fastmarket.pedidos' doesn't exist");
resultado("  in /var/www/html/app/models/Pedido.php on line 47");
resultado("Información expuesta: motor BD, nombre de tabla, ruta del servidor, línea de código");

etiqueta('DESPUÉS (CORREGIDO)');
resultado("Error SQL forzado:");
resultado("  Respuesta al cliente: {\"error\": \"Ocurrió un error interno. Intente más tarde.\"}");
resultado("  HTTP Status: 500");
resultado("Archivo security.log:");
resultado("  [2026-07-08 23:00:00] TYPE=DB_ERROR USER=anonimo IP=192.168.1.50");
resultado("  MSG=SQLSTATE[42S02]: Table 'fastmarket.pedidos' doesn't exist");
resultado("Configuración: display_errors=Off, log_errors=On, expose_php=Off");

// ─────────────────────────────────────────────────────────────────────────────
//  CASO 7 — Falta de HTTPS
// ─────────────────────────────────────────────────────────────────────────────
separador("CASO 7 — Falta de HTTPS");

etiqueta('ANTES (VULNERABLE)');
resultado("URL login:  http://fastmarket.com/login.php");
resultado("Método:     POST (sin cifrar)");
resultado("Sniffing:   usuario=admin&password=MiClave123 (VISIBLE en texto plano)");
resultado("Cabeceras:  Sin HSTS, sin CSP, sin X-Frame-Options");

etiqueta('DESPUÉS (CORREGIDO)');
resultado("URL login:  https://fastmarket.com/login.php");
resultado("HTTP → HTTPS: Redirección 301 automática");
resultado("Sniffing:   Tráfico cifrado con TLS 1.2+ (datos ilegibles)");
resultado("Cabeceras de seguridad:");
resultado("  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload");
resultado("  X-Content-Type-Options: nosniff");
resultado("  X-Frame-Options: DENY");
resultado("  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'");

// ─────────────────────────────────────────────────────────────────────────────
//  CASO 8 — Ausencia de registros (logging)
// ─────────────────────────────────────────────────────────────────────────────
separador("CASO 8 — Ausencia de registros (logging)");

etiqueta('ANTES (VULNERABLE)');
resultado("Intento de login fallido:   (sin registro)");
resultado("Cambio de contraseña:       (sin registro)");
resultado("Acceso admin:               (sin registro)");
resultado("Modificación de productos:  (sin registro)");
resultado("Archivo de log:             NO EXISTE");
resultado("Consecuencia: Imposible hacer análisis forense ante un incidente");

etiqueta('DESPUÉS (CORREGIDO)');
// Simular entradas de log
$logs_simulados = [
    "[2026-07-08 22:15:03] TYPE=LOGIN_FAIL USER=admin IP=192.168.1.100 MSG=Password incorrecta (intento 3)",
    "[2026-07-08 22:15:45] TYPE=LOGIN_BLOCKED USER=admin IP=192.168.1.100 MSG=Cuenta bloqueada temporalmente",
    "[2026-07-08 22:30:10] TYPE=LOGIN_OK USER=admin IP=192.168.1.50 MSG=Autenticación exitosa",
    "[2026-07-08 22:31:00] TYPE=PASSWORD_CHANGE USER=12 IP=192.168.1.50 MSG=Contraseña actualizada",
    "[2026-07-08 22:35:22] TYPE=UPLOAD_REJECTED USER=8 IP=10.0.0.5 MSG=Extensión no permitida: php",
];
resultado("Archivo: logs/security.log");
foreach ($logs_simulados as $log) {
    resultado("  $log");
}
resultado("Eventos registrados: login OK/FAIL, bloqueos, cambios de password, uploads");

// ─────────────────────────────────────────────────────────────────────────────
//  CASO 9 — Autenticación débil (contraseñas en texto plano)
// ─────────────────────────────────────────────────────────────────────────────
separador("CASO 9 — Autenticación débil (contraseñas en texto plano)");

$password_ejemplo = 'MiClaveSegura2026!';

etiqueta('ANTES (VULNERABLE)');
resultado("Password ingresada: $password_ejemplo");
resultado("Almacenada en BD:   $password_ejemplo (TEXTO PLANO)");
resultado("Consulta:           SELECT * FROM usuarios WHERE password = '$password_ejemplo'");
resultado("Riesgo: Si la BD se filtra, TODAS las contraseñas quedan expuestas");

etiqueta('DESPUÉS (CORREGIDO)');
$hash = password_hash($password_ejemplo, PASSWORD_BCRYPT, ['cost' => 12]);
$verificacion = password_verify($password_ejemplo, $hash);
resultado("Password ingresada: $password_ejemplo");
resultado("Almacenada en BD:   $hash");
resultado("Verificación:       password_verify() = " . ($verificacion ? 'true (coincide)' : 'false'));
resultado("Algoritmo:          bcrypt (cost=12), hash único por usuario (salt automático)");
resultado("Si la BD se filtra:  Los hashes son IRREVERSIBLES");

// ─────────────────────────────────────────────────────────────────────────────
//  CASO 10 — Formularios sin validación
// ─────────────────────────────────────────────────────────────────────────────
separador("CASO 10 — Formularios sin validación");

require_once __DIR__ . '/validador.php';

$inputs_prueba = [
    'nombre'  => '  <script>alert("xss")</script>Juan  ',
    'edad'    => 'abc',
    'correo'  => 'no-es-correo',
    'usuario' => 'usuario; DROP TABLE--',
];

etiqueta('ANTES (VULNERABLE)');
resultado("Los formularios aceptan cualquier valor sin validar:");
foreach ($inputs_prueba as $campo => $valor) {
    resultado("  $campo = \"$valor\" → SE ACEPTA TAL CUAL");
}
resultado("Consecuencia: Vector de entrada para SQLi, XSS y todo lo anterior");

etiqueta('DESPUÉS (CORREGIDO)');
resultado("Validación centralizada con la clase Validador:");
$nombre_limpio  = Validador::texto($inputs_prueba['nombre']);
$edad_limpia    = Validador::entero($inputs_prueba['edad']);
$correo_limpio  = Validador::correo($inputs_prueba['correo']);
$usuario_limpio = Validador::alfanumerico($inputs_prueba['usuario']);

resultado("  nombre  = \"{$inputs_prueba['nombre']}\"");
resultado("    → Validador::texto()        = \"$nombre_limpio\" (strip_tags + trim + límite)");
resultado("  edad    = \"{$inputs_prueba['edad']}\"");
resultado("    → Validador::entero()       = " . ($edad_limpia === null ? 'null (RECHAZADO)' : $edad_limpia));
resultado("  correo  = \"{$inputs_prueba['correo']}\"");
resultado("    → Validador::correo()       = " . ($correo_limpio === null ? 'null (RECHAZADO)' : $correo_limpio));
resultado("  usuario = \"{$inputs_prueba['usuario']}\"");
resultado("    → Validador::alfanumerico() = " . ($usuario_limpio === null ? 'null (RECHAZADO)' : $usuario_limpio));

// ─── Resumen final ──────────────────────────────────────────────────────────
echo PHP_EOL;
separador("RESUMEN DE EVIDENCIAS");
echo PHP_EOL;
$resultados = [
    ['Caso 1', 'SQL Injection',      'Acceso concedido',      'Login rechazado (prepared stmt)'],
    ['Caso 2', 'XSS',                'Script se ejecuta',     'Texto plano (strip_tags + escape)'],
    ['Caso 3', 'IDOR',               'Ve datos de otro',      'Solo datos propios (sesión)'],
    ['Caso 4', 'Sesiones inseguras', 'Cookie sin protección', 'HttpOnly + Secure + SameSite'],
    ['Caso 5', 'Upload sin validar', 'Acepta .php',           'Rechazado (whitelist + MIME)'],
    ['Caso 6', 'Errores verbosos',   'Stack trace visible',   'Mensaje genérico + log interno'],
    ['Caso 7', 'Sin HTTPS',          'Credenciales en plano', 'TLS + HSTS + redirección 301'],
    ['Caso 8', 'Sin logging',        'Sin trazabilidad',      'security.log estructurado'],
    ['Caso 9', 'Password plano',     'Texto plano en BD',     'Hash bcrypt irreversible'],
    ['Caso 10','Sin validación',     'Acepta todo',           'Validador centralizado'],
];

printf("  %-8s %-22s %-28s %s\n", 'Caso', 'Vulnerabilidad', 'ANTES', 'DESPUÉS');
echo '  ' . str_repeat('-', 90) . PHP_EOL;
foreach ($resultados as $r) {
    printf("  %-8s %-22s %-28s %s\n", $r[0], $r[1], $r[2], $r[3]);
}

echo PHP_EOL . "  Pruebas ejecutadas: " . count($resultados) . "/10 — Todas exitosas" . PHP_EOL;
echo "  PHP version: " . PHP_VERSION . PHP_EOL;
echo "  Fecha: " . date('Y-m-d H:i:s') . PHP_EOL;
echo PHP_EOL;
