-- schema.sql — Esquema de base de datos para FastMarket S.A.C.
-- Ejecutar con: mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS fastmarket
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE fastmarket;

-- Tabla de usuarios con campos de seguridad
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario VARCHAR(50) NOT NULL UNIQUE,
    correo VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL COMMENT 'Hash bcrypt ($2y$12$...)',
    rol ENUM('cliente', 'admin') NOT NULL DEFAULT 'cliente',
    intentos_fallidos INT NOT NULL DEFAULT 0,
    bloqueado_hasta DATETIME DEFAULT NULL COMMENT 'Bloqueo temporal tras 5 intentos fallidos',
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    actualizado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_usuario (usuario),
    INDEX idx_correo (correo)
) ENGINE=InnoDB;

-- Tabla de clientes (datos de perfil)
CREATE TABLE IF NOT EXISTS clientes (
    id INT PRIMARY KEY COMMENT 'Mismo ID que usuarios',
    nombre VARCHAR(100) NOT NULL,
    correo VARCHAR(255) NOT NULL,
    direccion VARCHAR(500) DEFAULT NULL,
    telefono VARCHAR(20) DEFAULT NULL,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (id) REFERENCES usuarios(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Tabla de comentarios (protegida contra XSS)
CREATE TABLE IF NOT EXISTS comentarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    contenido VARCHAR(500) NOT NULL COMMENT 'Contenido sanitizado (strip_tags)',
    creado_en DATETIME NOT NULL,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    INDEX idx_usuario_id (usuario_id),
    INDEX idx_creado_en (creado_en)
) ENGINE=InnoDB;

-- Tabla de productos
CREATE TABLE IF NOT EXISTS productos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(200) NOT NULL,
    descripcion TEXT,
    precio DECIMAL(10,2) NOT NULL,
    stock INT NOT NULL DEFAULT 0,
    imagen VARCHAR(255) DEFAULT NULL COMMENT 'Nombre del archivo en uploads_privados/',
    activo TINYINT(1) NOT NULL DEFAULT 1,
    creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_activo (activo)
) ENGINE=InnoDB;

-- Usuario de aplicación con privilegios mínimos (NO usar root)
-- Ejecutar como root:
-- CREATE USER 'fastmarket_app'@'localhost' IDENTIFIED BY 'CAMBIAR_ESTA_CLAVE';
-- GRANT SELECT, INSERT, UPDATE, DELETE ON fastmarket.* TO 'fastmarket_app'@'localhost';
-- FLUSH PRIVILEGES;
