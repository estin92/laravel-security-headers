<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use InvalidArgumentException;

class InvalidPermissionsPolicy extends InvalidArgumentException
{
    public static function invalidFeature(string $feature): self
    {
        return new self('Invalid Permissions-Policy feature: '.self::escape($feature));
    }

    public static function invalidOrigin(string $origin): self
    {
        return new self('Invalid Permissions-Policy origin: '.self::escape($origin));
    }

    public static function wildcardMustBeAlone(string $feature): self
    {
        return new self("The {$feature} allowlist may only use * on its own.");
    }

    public static function keywordMustUseEnum(string $keyword): self
    {
        return new self("Use the Keyword enum for the {$keyword} keyword, not a raw string.");
    }

    private static function escape(string $value): string
    {
        return (string) json_encode($value);
    }
}
