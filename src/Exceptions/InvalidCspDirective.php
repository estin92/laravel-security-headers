<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;

class InvalidCspDirective extends InvalidArgumentException
{
    public static function invalidName(string $name): self
    {
        return new self('Invalid CSP directive name: '.MessageValue::escape($name));
    }

    public static function invalidSource(string $source): self
    {
        return new self('Invalid CSP source: '.MessageValue::escape($source));
    }

    public static function invalidNonce(): self
    {
        return new self('The CSP nonce is not a valid token.');
    }

    public static function missingNonce(): self
    {
        return new self('The policy requires a nonce, but none was supplied.');
    }

    public static function conflictingNone(string $directive): self
    {
        return new self("The {$directive} directive cannot combine 'none' with other sources.");
    }

    public static function sourcesOnValuelessDirective(string $directive): self
    {
        return new self("The {$directive} directive cannot be both valueless and carry sources or a nonce.");
    }

    public static function keywordMustUseEnum(string $source): self
    {
        return new self('Use the Keyword enum for the CSP keyword source: '.MessageValue::escape($source));
    }
}
