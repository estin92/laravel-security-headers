<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Support;

class IntegerConfig
{
    // .env always arrives as a string, so convert only a clean positive integer and
    // leave anything else untouched for the config validator to reject loudly.
    public static function parse(mixed $value): mixed
    {
        if (is_int($value)) {
            return $value;
        }

        if (! is_string($value) || preg_match('/^[1-9][0-9]*$/', $value) !== 1) {
            return $value;
        }

        $integer = (int) $value;

        return (string) $integer === $value ? $integer : $value;
    }
}
