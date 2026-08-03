<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;

class InvalidCoop extends InvalidArgumentException
{
    public static function notReportOnlyValue(string $value): self
    {
        return new self('A COOP report-only channel cannot use the enforcement-only value: '.MessageValue::escape($value));
    }

    public static function reportOnlyMissingDestination(): self
    {
        return new self('An enabled report-only COOP channel must name a reporting destination.');
    }
}
