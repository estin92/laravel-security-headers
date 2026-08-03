<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use InvalidArgumentException;

class InvalidCoep extends InvalidArgumentException
{
    public static function unsafeNoneWithReporting(): self
    {
        return new self('A COEP channel set to unsafe-none cannot carry a reporting endpoint.');
    }

    public static function reportOnlyMissingDestination(): self
    {
        return new self('An enabled report-only COEP channel must name a reporting destination.');
    }
}
