<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;

class InvalidReportToGroup extends InvalidArgumentException
{
    public static function invalidName(string $name): self
    {
        return new self('A Report-To group name must match [a-z][a-z0-9-]*: '.MessageValue::escape($name));
    }

    public static function notAnArray(string $key): self
    {
        return new self('A Report-To group definition must be an array: '.MessageValue::escape($key));
    }

    public static function missingMaxAge(string $group): self
    {
        return new self('The Report-To group is missing a max_age: '.MessageValue::escape($group));
    }

    public static function invalidMaxAge(string $group, mixed $value): self
    {
        return new self('The Report-To group '.MessageValue::escape($group).' has an invalid max_age (non-negative integer within range required): '.MessageValue::escape(is_scalar($value) ? (string) $value : gettype($value)));
    }

    public static function invalidIncludeSubdomains(string $group, mixed $value): self
    {
        return new self('The Report-To group '.MessageValue::escape($group).' has a non-boolean include_subdomains: '.MessageValue::escape(is_scalar($value) ? (string) $value : gettype($value)));
    }

    public static function unknownGroupKey(string $group, string $key): self
    {
        return new self('The Report-To group '.MessageValue::escape($group).' has an unknown key: '.MessageValue::escape($key));
    }

    public static function endpointsNotAList(string $group): self
    {
        return new self('The Report-To group endpoints must be an ordered list, not a keyed array: '.MessageValue::escape($group));
    }

    public static function emptyEndpoints(string $group): self
    {
        return new self('The Report-To group must declare at least one endpoint: '.MessageValue::escape($group));
    }

    public static function duplicateEndpoint(string $group, string $name): self
    {
        return new self('The Report-To group '.MessageValue::escape($group).' references an endpoint more than once: '.MessageValue::escape($name));
    }

    public static function invalidReference(string $configPath, mixed $value): self
    {
        return new self('The '.MessageValue::escape($configPath).' report_to_group must be a string or absent, got: '.MessageValue::escape(is_scalar($value) ? (string) $value : gettype($value)));
    }

    public static function unknownGroup(string $reference): self
    {
        return new self('No Report-To group is registered under the key: '.MessageValue::escape($reference));
    }

    public static function duplicateEmittedName(string $name): self
    {
        return new self('More than one Report-To group emits the same name: '.MessageValue::escape($name));
    }
}
