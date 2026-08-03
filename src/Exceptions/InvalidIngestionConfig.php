<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;
use Throwable;

class InvalidIngestionConfig extends InvalidArgumentException
{
    public static function limitOutOfRange(string $key, int $min, int $max): self
    {
        return new self("The ingestion limit {$key} must be an integer between {$min} and {$max}.");
    }

    public static function notInSet(string $key, string $value): self
    {
        return new self("The ingestion setting {$key} has an unsupported value: ".MessageValue::escape($value));
    }

    public static function notABoolean(string $key): self
    {
        return new self("The ingestion setting {$key} must be true or false.");
    }

    public static function notAPositiveInt(string $key): self
    {
        return new self("The ingestion setting {$key} must be a positive integer.");
    }

    public static function badCorsOrigin(string $origin): self
    {
        return new self('An allowed CORS origin must be an https (or trustworthy-local http) scheme+host origin: '.MessageValue::escape($origin));
    }

    public static function unregisteredLimiter(string $name): self
    {
        return new self('The configured ingestion rate limiter is not registered: '.MessageValue::escape($name));
    }

    public static function delegated(Throwable $previous): self
    {
        return new self($previous->getMessage(), 0, $previous);
    }
}
