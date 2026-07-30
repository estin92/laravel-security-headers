<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use RuntimeException;

class InvalidCspPolicy extends RuntimeException
{
    public static function configuredValueIsInvalid(mixed $value): self
    {
        $given = is_string($value) ? $value : get_debug_type($value);

        return new self("The configured CSP policy must be a class extending CspPolicy, {$given} given.");
    }

    public static function resolvedToWrongType(string $class, string $actual): self
    {
        return new self("The configured CSP policy {$class} resolved to {$actual}, which is not a CspPolicy.");
    }
}
