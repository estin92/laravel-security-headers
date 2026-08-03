<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;

class InvalidReportTypeEnum extends InvalidArgumentException
{
    public static function notAnEnum(string $class): self
    {
        return new self('The configured report type must be an enum: '.MessageValue::escape($class));
    }

    public static function notStringBacked(string $class): self
    {
        return new self('The configured report type enum must be string-backed: '.MessageValue::escape($class));
    }

    public static function missingContract(string $class): self
    {
        return new self('The configured report type enum must implement ReportTypeContract: '.MessageValue::escape($class));
    }

    public static function invalidValue(string $class, string $value): self
    {
        return new self('The report type enum '.MessageValue::escape($class).' has a value that must match [a-z][a-z0-9-]* and stay within 64 bytes: '.MessageValue::escape($value));
    }
}
