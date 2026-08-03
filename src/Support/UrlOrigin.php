<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Support;

class UrlOrigin
{
    private const DEFAULT_PORTS = ['http' => 80, 'https' => 443];

    public static function from(?string $url): ?string
    {
        if ($url === null || $url === '') {
            return null;
        }

        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        $scheme = strtolower($parts['scheme']);
        $origin = $scheme.'://'.strtolower($parts['host']);

        if (isset($parts['port']) && $parts['port'] !== (self::DEFAULT_PORTS[$scheme] ?? null)) {
            $origin .= ':'.$parts['port'];
        }

        // The full url still holds it even if this is too long for the field
        if (strlen($origin) > 255) {
            return null;
        }

        return $origin;
    }
}
