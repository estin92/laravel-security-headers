<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Viewer;

final class PageLimit
{
    public const MIN = 1;

    public const MAX = 100;

    public const DEFAULT = 50;

    public static function from(mixed $raw): int
    {
        if (! is_int($raw) && ! (is_string($raw) && ctype_digit($raw))) {
            return self::DEFAULT;
        }

        $value = (int) $raw;

        if ($value < self::MIN) {
            return self::DEFAULT;
        }

        return min($value, self::MAX);
    }
}
