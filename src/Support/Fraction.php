<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Support;

class Fraction
{
    public static function parse(mixed $value): ?float
    {
        if (is_int($value) || is_float($value)) {
            $float = (float) $value;

            if (is_finite($float) && $float >= 0.0 && $float <= 1.0) {
                return $float;
            }

            return null;
        }

        // The grammar bounds the value to [0,1] itself, so no separate range check is needed.
        if (is_string($value) && preg_match('/\A(?:0(?:\.[0-9]+)?|1(?:\.0+)?)\z/', $value) === 1) {
            return (float) $value;
        }

        return null;
    }
}
