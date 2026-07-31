<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;

class InvalidReportingEndpoint extends InvalidArgumentException
{
    public static function unknownReference(string $name): self
    {
        return new self('No reporting endpoint is registered under the name: '.MessageValue::escape($name));
    }

    public static function invalidReference(string $channel): self
    {
        return new self("The {$channel} channel's reporting_endpoint must be a string or absent.");
    }

    public static function malformedUrl(string $url): self
    {
        return new self('A reporting endpoint url is malformed: '.MessageValue::escape($url));
    }

    public static function invalidName(string $name): self
    {
        return new self('Invalid reporting endpoint name: '.MessageValue::escape($name));
    }

    public static function missingUrl(string $name): self
    {
        return new self('The reporting endpoint has no url: '.MessageValue::escape($name));
    }

    public static function nonHttpUrl(string $url): self
    {
        return new self('A reporting endpoint url must be http(s): '.MessageValue::escape($url));
    }

    public static function insecureUrl(string $url): self
    {
        return new self('A reporting endpoint url must use https outside local origins: '.MessageValue::escape($url));
    }

    public static function urlHasCredentials(string $url): self
    {
        return new self('A reporting endpoint url must not carry credentials: '.MessageValue::escape($url));
    }

    public static function urlHasFragment(string $url): self
    {
        return new self('A reporting endpoint url must not carry a fragment: '.MessageValue::escape($url));
    }

    public static function injectionInValue(string $value): self
    {
        return new self('A reporting endpoint value contains illegal characters: '.MessageValue::escape($value));
    }
}
