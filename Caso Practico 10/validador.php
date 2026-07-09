<?php
declare(strict_types=1);

final class Validador
{
    public static function texto(string $valor, int $max = 255): string
    {
        $valor = trim($valor);
        $valor = strip_tags($valor);
        return mb_substr($valor, 0, $max);
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
