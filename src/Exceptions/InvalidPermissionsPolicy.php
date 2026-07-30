<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;

class InvalidPermissionsPolicy extends InvalidArgumentException
{
    public static function invalidFeature(string $feature): self
    {
        return new self('Invalid Permissions-Policy feature: '.MessageValue::escape($feature));
    }

    public static function invalidOrigin(string $origin): self
    {
        return new self('Invalid Permissions-Policy origin: '.MessageValue::escape($origin));
    }

    public static function wildcardMustBeAlone(string $feature): self
    {
        return new self("The {$feature} allowlist may only use * on its own.");
    }

    public static function keywordMustUseEnum(string $keyword): self
    {
        return new self("Use the Keyword enum for the {$keyword} keyword, not a raw string.");
    }
}
