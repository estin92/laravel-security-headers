<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Support;

class NonNegativeInt
{
    public static function parse(mixed $value): ?int
    {
        if (is_int($value) && $value >= 0) {
            return $value;
        }

        // (int) on a string bigger than PHP_INT_MAX quietly gives the wrong number, so check the range.
        if (is_string($value) && preg_match('/\A(0|[1-9][0-9]*)\z/', $value) === 1) {
            $int = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]);

            if ($int !== false) {
                return $int;
            }
        }

        return null;
    }
}
