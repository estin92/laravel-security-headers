<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;

class InvalidNel extends InvalidArgumentException
{
    public static function notAnArray(mixed $definition): self
    {
        return new self('The NEL policy definition must be an array, got: '.MessageValue::escape(gettype($definition)));
    }

    public static function unknownKey(string $key): self
    {
        return new self('The NEL policy has an unknown key: '.MessageValue::escape($key));
    }

    public static function missingMaxAge(): self
    {
        return new self('The NEL policy is missing a max_age.');
    }

    public static function invalidMaxAge(mixed $value): self
    {
        return new self('The NEL policy max_age must be a non-negative integer within range, got: '.MessageValue::escape(is_scalar($value) ? (string) $value : gettype($value)));
    }

    public static function missingReportToGroup(): self
    {
        return new self('A NEL policy with a positive max_age must name a non-empty report_to_group.');
    }

    public static function invalidReportToGroup(mixed $value): self
    {
        return new self('The NEL policy report_to_group must be a non-empty string, got: '.MessageValue::escape(is_scalar($value) ? (string) $value : gettype($value)));
    }

    public static function removalFieldNotDefault(string $field): self
    {
        return new self('A NEL removal (max_age 0) must leave '.MessageValue::escape($field).' at its default.');
    }

    public static function invalidIncludeSubdomains(mixed $value): self
    {
        return new self('The NEL policy include_subdomains must be a boolean, got: '.MessageValue::escape(is_scalar($value) ? (string) $value : gettype($value)));
    }

    public static function invalidSuccessFraction(mixed $value): self
    {
        return new self('The NEL policy success_fraction must be a number in [0,1], got: '.MessageValue::escape(is_scalar($value) ? (string) $value : gettype($value)));
    }

    public static function invalidFailureFraction(mixed $value): self
    {
        return new self('The NEL policy failure_fraction must be a number in [0,1], got: '.MessageValue::escape(is_scalar($value) ? (string) $value : gettype($value)));
    }

    public static function groupIsRemoval(string $group): self
    {
        return new self('A NEL policy cannot deliver to a Report-To group being removed: '.MessageValue::escape($group));
    }

    public static function groupLifetimeTooShort(string $group): self
    {
        return new self('The NEL policy outlives its Report-To group '.MessageValue::escape($group).'; the group max_age must be at least the NEL max_age.');
    }

    public static function groupSubdomainsMismatch(string $group): self
    {
        return new self('The NEL policy collects subdomains but its Report-To group '.MessageValue::escape($group).' does not include subdomains.');
    }

    public static function compileWithoutGroup(): self
    {
        return new self('A positive NEL policy must be compiled with its resolved Report-To group.');
    }

    public static function compileRemovalWithGroup(): self
    {
        return new self('A NEL removal must be compiled without a group.');
    }

    public static function unknownGroup(string $reference): self
    {
        return new self('The NEL report_to_group references an unregistered group: '.MessageValue::escape($reference));
    }
}
