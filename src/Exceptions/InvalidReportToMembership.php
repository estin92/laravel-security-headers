<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;

class InvalidReportToMembership extends InvalidArgumentException
{
    public static function notAnEndpointReference(mixed $membership): self
    {
        return new self('A Report-To group endpoint must be a name or an {endpoint, priority?, weight?} array, got: '.MessageValue::escape(is_string($membership) ? $membership : gettype($membership)));
    }

    public static function unknownEndpoint(string $name): self
    {
        return new self('A Report-To group references an unknown endpoint: '.MessageValue::escape($name));
    }

    public static function invalidRoutingValue(string $key, mixed $value): self
    {
        return new self("A Report-To endpoint {$key} must be a non-negative integer, got: ".MessageValue::escape(is_scalar($value) ? (string) $value : gettype($value)));
    }

    public static function unknownMembershipKey(string $key): self
    {
        return new self('A Report-To group endpoint has an unknown key: '.MessageValue::escape($key));
    }
}
