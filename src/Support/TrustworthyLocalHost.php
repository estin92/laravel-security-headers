<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Support;

class TrustworthyLocalHost
{
    public static function matches(string $host): bool
    {
        $host = strtolower($host);

        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            return true;
        }

        if ($host === '[::1]') {
            return true;
        }

        // Must be a real IPv4 in 127.0.0.0/8.
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return false;
        }

        return str_starts_with($host, '127.');
    }
}
