<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Support;

class Origin
{
    private const DEFAULT_PORTS = ['http' => 80, 'https' => 443];

    // http is only trusted from a local host; everything else must be https.
    public static function normalize(string $origin): ?string
    {
        $parts = parse_url($origin);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        if (array_any(['user', 'pass', 'path', 'query', 'fragment'], fn($extra) => isset($parts[$extra]))) {
            return null;
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);

        if ($scheme !== 'https' && ! ($scheme === 'http' && TrustworthyLocalHost::matches($host))) {
            return null;
        }

        $port = isset($parts['port']) && $parts['port'] !== self::DEFAULT_PORTS[$scheme]
            ? ':'.$parts['port']
            : '';

        return $scheme.'://'.$host.$port;
    }
}
