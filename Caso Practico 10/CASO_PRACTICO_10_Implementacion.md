# Caso Práctico 10 — FastMarket S.A.C.
## Diagnóstico, Matriz de Riesgos y Solución Técnica (OWASP Top 10 – 2021)

**Curso:** Desarrollo de Sistemas Web Nativos de la Nube (CNA)
**Stack:** HTML / CSS / JavaScript / PHP / MySQL
**Fecha:** 07/07/2026

---

## 1. Introducción

FastMarket S.A.C. reportó incidentes de seguridad en su plataforma de e-commerce. Este
documento analiza los 10 casos detectados, los clasifica según **OWASP Top 10 (2021)**,
calcula su riesgo y entrega **código PHP/MySQL corregido**, listo para producción, junto
con la arquitectura de seguridad y el plan de pruebas.

Todo el código corregido usa:
- **PDO con prepared statements** (nunca concatenación de SQL).
- **`password_hash()` / `password_verify()`** (bcrypt) para credenciales.
- **`htmlspecialchars()` / sanitización de entrada** contra XSS.
- **Control de sesión reforzado** (`HttpOnly`, `Secure`, `SameSite=Strict`).
- **Validación de archivos por contenido real (MIME/finfo)**, no por extensión.
- **Manejo de errores centralizado** sin exponer trazas al usuario.
- **Logging estructurado** de eventos de seguridad.
- **Redirección forzada a HTTPS** y cabeceras de seguridad (HSTS, CSP, etc.).

> **Nota de compatibilidad:** el código requiere PHP ≥ 7.4 (recomendado 8.1+) con las
> extensiones `pdo_mysql`, `openssl` y `fileinfo` habilitadas. Todos los ejemplos son
> autocontenidos y usan solo funciones nativas de PHP (sin dependencias externas) para
> evitar problemas de compatibilidad entre entornos.

---

## 2. Matriz de Riesgos (Actividad 1 — Producto esperado)

| # | Caso | Vulnerabilidad | Clasificación OWASP 2021 | Impacto | Probabilidad | Riesgo |
|---|------|-----------------|--------------------------|---------|---------------|--------|
| 1 | SQL Injection | Consulta armada por concatenación | **A03:2021 – Injection** | Alto (fuga/borrado de BD) | Alta | **Crítico** |
| 2 | XSS | Comentarios sin sanitizar, reflejados a todos los usuarios | **A03:2021 – Injection (XSS)** | Alto (robo de sesión, phishing) | Alta | **Crítico** |
| 3 | Broken Access Control (IDOR) | `id` de perfil manipulable en la URL | **A01:2021 – Broken Access Control** | Alto (fuga de datos de clientes) | Alta | **Crítico** |
| 4 | Gestión insegura de sesiones | Cookie `PHPSESSID` sin `HttpOnly`/`Secure`/`SameSite` | **A05:2021 – Security Misconfiguration** | Medio-Alto (secuestro de sesión) | Media | **Alto** |
| 5 | Carga de archivos sin validación | Permite subir `.php` (webshell) | **A05:2021 – Security Misconfiguration** | Muy alto (RCE, control del servidor) | Media | **Crítico** |
| 6 | Configuración insegura (errores verbosos) | Stack trace / errores SQL visibles | **A05:2021 – Security Misconfiguration** | Medio (fuga de info técnica) | Alta | **Alto** |
| 7 | Falta de HTTPS | Login viaja en texto plano por HTTP | **A02:2021 – Cryptographic Failures** | Alto (interceptación de credenciales) | Media | **Alto** |
| 8 | Ausencia de registros | No hay logging de eventos de seguridad | **A09:2021 – Security Logging and Monitoring Failures** | Medio (no hay trazabilidad/forense) | Alta | **Alto** |
| 9 | Autenticación débil | Contraseñas en texto plano | **A02:2021 – Cryptographic Failures** | Muy alto (compromiso masivo de cuentas) | Media | **Crítico** |
| 10 | Consultas/formularios sin validación | Acepta HTML, scripts, SQL en cualquier campo | **A03:2021 – Injection / A04:2021 – Insecure Design** | Alto (vector de entrada a todo lo anterior) | Alta | **Crítico** |

**Escala:** Riesgo = Impacto × Probabilidad → Crítico (acción inmediata), Alto (corto plazo), Medio (mediano plazo).

---

## 3. Arquitectura de seguridad propuesta (Actividad 2)

```
                         ┌───────────────────────────┐
                         │        Cliente (HTTPS)     │
                         └──────────────┬─────────────┘
                                        │ TLS 1.2+/HSTS
                         ┌──────────────▼─────────────┐
                         │  WAF / Reverse Proxy        │  ← filtra payloads SQLi/XSS conocidos
                         │  (Nginx + ModSecurity)      │
                         └──────────────┬─────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │      Capa de Aplicación      │
                         │  - Autenticación (bcrypt)     │
                         │  - Autorización (RBAC)        │
                         │  - Validación de entrada       │
                         │  - Sanitización de salida       │
                         │  - Gestión de sesiones segura     │
                         │  - Manejo centralizado de errores  │
                         └──────────────┬─────────────┘
                                        │ PDO (prepared statements)
                         ┌──────────────▼─────────────┐
                         │        MySQL (usuario con    │
                         │        privilegios mínimos)   │
                         └───────────────────────────┘
                                        │
                         ┌──────────────▼─────────────┐
                         │   Logging & Monitoreo         │
                         │  (auth.log, access.log, SIEM)  │
                         └───────────────────────────┘
```

**Controles por capa:**
- **Preventivos:** prepared statements, validación/sanitización, `password_hash`, HTTPS, cookies seguras, validación de archivos, RBAC.
- **Detectivos:** logging de eventos, alertas por múltiples intentos fallidos, monitoreo de integridad de archivos subidos.
- **Correctivos:** bloqueo temporal de cuenta tras N intentos fallidos, invalidación de sesiones comprometidas, cuarentena de archivos sospechosos.

---

## 4. Configuración base común (usar en todos los módulos)

### 4.1 Conexión segura a BD (`db.php`)

```php
<?php
// db.php
declare(strict_types=1);

function getDbConnection(): PDO
{
    $host = 'localhost';
    $db   = 'fastmarket';
    $user = 'fastmarket_app'; // usuario con privilegios mínimos, NO root
    $pass = getenv('DB_PASSWORD'); // nunca hardcodear credenciales
    $charset = 'utf8mb4';

    $dsn = "mysql:host=$host;dbname=$db;charset=$charset";
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false, // fuerza prepares reales del driver
    ];

    return new PDO($dsn, $user, $pass, $options);
}
```

### 4.2 Manejo centralizado de errores (Caso 6)

```php
<?php
// error_handler.php
declare(strict_types=1);

ini_set('display_errors', '0');   // nunca mostrar errores al cliente
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/logs/php_errors.log');

set_exception_handler(function (Throwable $e): void {
    logSecurityEvent('ERROR', 'Excepción no controlada: ' . $e->getMessage());
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Ocurrió un error interno. Intente más tarde.']);
    exit;
});

set_error_handler(function (int $severity, string $message, string $file, int $line): bool {
    logSecurityEvent('PHP_ERROR', "$message en $file:$line");
    return true; // evita que PHP imprima el error nativo
});
```

### 4.3 Logging de eventos de seguridad (Caso 8)

```php
<?php
// logger.php
declare(strict_types=1);

function logSecurityEvent(string $type, string $message, ?string $user = null): void
{
    $logDir = __DIR__ . '/logs';
    if (!is_dir($logDir)) {
        mkdir($logDir, 0750, true);
    }

    $entry = sprintf(
        "[%s] TYPE=%s USER=%s IP=%s MSG=%s\n",
        date('Y-m-d H:i:s'),
        $type,
        $user ?? 'anonimo',
        $_SERVER['REMOTE_ADDR'] ?? 'desconocida',
        $message
    );

    // append seguro, sin exponer ruta ni datos sensibles al usuario final
    file_put_contents($logDir . '/security.log', $entry, FILE_APPEND | LOCK_EX);
}
```
Eventos mínimos a registrar (Caso 8): login fallido, login exitoso, cambio de contraseña,
acceso a panel administrativo, alta/edición/borrado de productos, subida de archivos,
intentos de payload SQLi/XSS detectados.

### 4.4 Forzar HTTPS y cabeceras de seguridad (Caso 7)

```php
<?php
// security_headers.php
declare(strict_types=1);

// Redirigir a HTTPS si la petición llega por HTTP
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    $redirectUrl = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header('Location: ' . $redirectUrl, true, 301);
    exit;
}

header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';");
```

### 4.5 Sesiones seguras (Caso 4)

```php
<?php
// session_config.php
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
```

---

## 5. Casos específicos (Actividad 3 — Código corregido)

### Caso 1 — SQL Injection

**Vulnerable:**
```php
$sql = "SELECT * FROM usuarios WHERE usuario='$usuario' AND password='$password'";
```

**Corregido (PDO + prepared statement + verificación de hash):**
```php
<?php
declare(strict_types=1);
require 'db.php';
require 'logger.php';

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
```

---

### Caso 2 — Cross Site Scripting (XSS)

**Vulnerable:** el comentario `<script>alert('Hack')</script>` se guarda y se imprime tal cual.

**Corregido (sanitización en entrada + escape en salida + CSP ya definida en 4.4):**
```php
<?php
// guardar_comentario.php
declare(strict_types=1);
require 'db.php';
require 'logger.php';

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
```
> Con esto, `<script>alert('Hack')</script>` se guarda como texto plano y se muestra
> literalmente como `&lt;script&gt;alert('Hack')&lt;/script&gt;`, sin ejecutarse.

---

### Caso 3 — Broken Access Control (IDOR)

**Vulnerable:** `/cliente/perfil.php?id=12` permite ver el perfil de otro usuario cambiando el `id`.

**Corregido (autorización basada en sesión, no en parámetro de URL):**
```php
<?php
// perfil.php
declare(strict_types=1);
require 'session_config.php';
require 'db.php';
require 'logger.php';

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
```

---

### Caso 4 — Gestión insegura de sesiones

Ya cubierto en **4.5**. Adicionalmente, para invalidar sesiones en logout:

```php
<?php
// logout.php
declare(strict_types=1);
require 'session_config.php';

$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params['path'], $params['domain'], $params['secure'], $params['httponly']);
}
session_destroy();
header('Location: /login.php');
exit;
```

---

### Caso 5 — Carga de archivos sin validación

**Vulnerable:** acepta `malware.php` sin ninguna comprobación.

**Corregido (whitelist de extensión + validación de MIME real + renombrado + fuera de webroot ejecutable):**
```php
<?php
// upload_imagen.php
declare(strict_types=1);
require 'logger.php';

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

    if (!move_uploaded_file($archivo['tmp_name'], $destino)) {
        return ['ok' => false, 'msg' => 'No se pudo guardar el archivo.'];
    }

    logSecurityEvent('UPLOAD_OK', "Archivo guardado como $nombreSeguro", (string) $usuarioId);
    return ['ok' => true, 'archivo' => $nombreSeguro];
}
```
**Complemento de servidor (`uploads_privados/.htaccess`)** para Apache, o equivalente en Nginx,
para impedir la ejecución de scripts dentro del directorio de subidas:
```apache
# uploads_privados/.htaccess
php_flag engine off
<FilesMatch "\.(php|phtml|php3|php4|php5|phar)$">
    Require all denied
</FilesMatch>
```

---

### Caso 6 — Configuración insegura (errores verbosos)

Cubierto en **4.2**. Ejemplo de uso correcto al ejecutar una consulta:
```php
<?php
try {
    $stmt = $pdo->prepare('SELECT * FROM productos WHERE id = :id');
    $stmt->execute(['id' => $productoId]);
} catch (PDOException $e) {
    logSecurityEvent('DB_ERROR', $e->getMessage()); // detalle solo en el log
    http_response_code(500);
    exit('Ocurrió un problema al procesar su solicitud. Intente nuevamente.');
}
```
Además, en `php.ini` de producción:
```ini
display_errors = Off
display_startup_errors = Off
log_errors = On
expose_php = Off
```

---

### Caso 7 — Falta de HTTPS

Cubierto en **4.4** (redirección forzada + HSTS). Adicionalmente, marcar la cookie de sesión
como `Secure` (ver 4.5) y usar formularios con acción relativa (`action="/login.php"`) para
que nunca se sirvan sobre HTTP.

---

### Caso 8 — Ausencia de registros

Cubierto en **4.3**. Ejemplo de integración en cambio de contraseña:
```php
<?php
function cambiarPassword(int $usuarioId, string $passwordNueva, PDO $pdo): void
{
    $hash = password_hash($passwordNueva, PASSWORD_BCRYPT, ['cost' => 12]);
    $pdo->prepare('UPDATE usuarios SET password_hash = :h WHERE id = :id')
        ->execute(['h' => $hash, 'id' => $usuarioId]);

    logSecurityEvent('PASSWORD_CHANGE', 'Contraseña actualizada', (string) $usuarioId);
}
```

---

### Caso 9 — Autenticación débil (contraseñas en texto plano)

**Vulnerable:** `password` se guarda tal cual en la BD.

**Corregido (hash con bcrypt en el registro):**
```php
<?php
// registro.php
declare(strict_types=1);
require 'db.php';
require 'logger.php';

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
```
> Migración de contraseñas existentes en texto plano: se debe forzar un cambio de
> contraseña obligatorio en el primer login posterior a la migración, generando el hash
> en ese momento y nunca reutilizando el valor antiguo.

---

### Caso 10 — Formularios sin validación (caracteres especiales, HTML, scripts, SQL)

**Corregido (validación centralizada reutilizable en todos los formularios):**
```php
<?php
// validador.php
declare(strict_types=1);

final class Validador
{
    public static function texto(string $valor, int $max = 255): string
    {
        $valor = trim($valor);
        $valor = strip_tags($valor);              // elimina HTML/scripts
        return mb_substr($valor, 0, $max);        // limita longitud
    }

    public static function entero(mixed $valor): ?int
    {
        return filter_var($valor, FILTER_VALIDATE_INT) !== false
            ? (int) $valor
            : null;
    }

    public static function correo(string $valor): ?string
    {
        $valor = filter_var(trim($valor), FILTER_VALIDATE_EMAIL);
        return $valor !== false ? $valor : null;
    }

    public static function alfanumerico(string $valor): ?string
    {
        return preg_match('/^[a-zA-Z0-9_\-]{3,50}$/', $valor) === 1 ? $valor : null;
    }
}

// Uso típico en cualquier endpoint que reciba datos de formulario:
// $nombre  = Validador::texto($_POST['nombre'] ?? '');
// $edad    = Validador::entero($_POST['edad'] ?? null);
// $correo  = Validador::correo($_POST['correo'] ?? '');
// if ($correo === null) { /* rechazar solicitud */ }
```
Con esta capa **todos** los formularios (login, registro, comentarios, productos, reportes)
quedan protegidos de forma consistente, y al usarse siempre junto con **PDO prepared
statements** (Caso 1) y **`htmlspecialchars` en la salida** (Caso 2), se cierra el vector
de entrada descrito en el Caso 10.

---

## 6. Plan de pruebas (Actividad 4 — Evidencias antes/después)

| Prueba | Payload / acción | Resultado ANTES (vulnerable) | Resultado DESPUÉS (corregido) |
|--------|-------------------|-------------------------------|--------------------------------|
| SQL Injection | `' OR '1'='1` en usuario/clave | Acceso concedido sin credenciales válidas | Login rechazado; el valor se trata como texto literal (prepared statement) |
| XSS | `<script>alert(1)</script>` en comentario | Se ejecuta el script al cargar la página | Se muestra como texto `&lt;script&gt;alert(1)&lt;/script&gt;`, sin ejecución |
| Carga de archivo | `virus.php` | Archivo aceptado y accesible/ejecutable en el servidor | Rechazado: extensión y MIME no permitidos; solo se guardan imágenes reales |
| IDOR | `?id=15` (perfil de otro usuario) | Muestra datos de otro cliente | El `id` de la URL se ignora; se usa el `id` de la sesión autenticada |
| Acceso sin autenticación | Ingresar directamente a `/admin/panel.php` | Acceso permitido sin login | Redirección a `/login.php`; se registra el intento en el log de seguridad |
| Sniffing de credenciales | Captura de tráfico en login por HTTP | Usuario y clave visibles en texto plano | Tráfico cifrado por TLS; HTTP redirige a HTTPS automáticamente |
| Robo de cookie vía JS | `document.cookie` en consola del navegador | Devuelve el `PHPSESSID` | Cookie no accesible desde JS (`HttpOnly`); no viaja por HTTP (`Secure`) |
| Fuerza bruta | 10 intentos de login fallidos seguidos | Sin límite, sin registro | Cuenta bloqueada 15 min tras 5 intentos; todo intento queda registrado |
| Errores de servidor | Forzar un error SQL | Se muestra `Fatal Error / Stack Trace` con detalles de la BD | Se muestra mensaje genérico; el detalle solo queda en `security.log` |
| Fuga de credenciales en BD | Consultar tabla `usuarios` directamente | Contraseña visible en texto plano | Solo se almacena el hash bcrypt (`$2y$12$...`), irreversible |

---

## 7. Conclusiones

1. Las 10 vulnerabilidades detectadas se concentran principalmente en **A03 (Injection)**,
   **A01 (Broken Access Control)**, **A05 (Security Misconfiguration)** y **A02
   (Cryptographic Failures)** del OWASP Top 10 2021, lo que confirma que el riesgo mayor
   proviene de la falta de validación de entrada y de controles de acceso a nivel de
   servidor, no del frontend.
2. La corrección más crítica y de mayor retorno es migrar **todas** las consultas a
   **prepared statements con PDO**, ya que elimina de raíz el vector de SQL Injection y
   reduce el impacto de otros casos (Caso 1 y Caso 10).
3. El uso combinado de **`password_hash`**, **cookies con `HttpOnly`/`Secure`/`SameSite`**
   y **HTTPS forzado** cierra la cadena completa de robo de identidad (Casos 4, 7 y 9).
4. La **validación de archivos por contenido real (MIME) y no por extensión**, junto con la
   denegación de ejecución en la carpeta de subidas, evita la instalación de webshells
   (Caso 5), que era el riesgo de mayor severidad técnica (posible control total del servidor).
5. El **logging centralizado** (Caso 8) es indispensable no solo como control detectivo,
   sino como evidencia forense y de cumplimiento ante futuros incidentes.

## 8. Recomendaciones

- Ejecutar un **análisis de dependencias** (Composer/librerías) para descartar componentes
  vulnerables (**A06:2021 – Vulnerable and Outdated Components**), no cubierto explícitamente
  en el caso pero relevante para el stack PHP/MySQL.
- Implementar **rate limiting** a nivel de proxy/WAF para mitigar fuerza bruta y DoS.
- Establecer un **usuario de base de datos con privilegios mínimos** (sin `DROP`, `GRANT`,
  ni acceso a otras bases) para la aplicación web.
- Programar **pentesting periódico** y análisis estático de código (SAST) como parte del
  ciclo de despliegue (CI/CD).
- Capacitar al equipo de desarrollo en **Secure SDLC** para que estos controles se apliquen
  desde el diseño y no como parche posterior.
