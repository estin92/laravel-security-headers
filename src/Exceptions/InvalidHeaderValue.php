<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;

class InvalidHeaderValue extends InvalidArgumentException
{
    public static function containsControlCharacters(string $header, string $value): self
    {
        return new self("The {$header} value contains control characters: ".MessageValue::escape($value));
    }

    public static function notInValueSet(string $header, string $value): self
    {
        return new self("Invalid value for {$header}: ".MessageValue::escape($value));
    }
}
