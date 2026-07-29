<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Headers;

class Hsts
{
    // One year in seconds.
    private const DEFAULT_MAX_AGE = 31536000;

    /**
     * @param  array<mixed>  $config
     */
    public function __construct(private readonly array $config) {}

    public function compile(): ?string
    {
        if (($this->config['enabled'] ?? false) !== true) {
            return null;
        }

        $value = "max-age={$this->maxAge()}";

        if (($this->config['include_subdomains'] ?? false) === true) {
            $value .= '; includeSubDomains';
        }

        if (($this->config['preload'] ?? false) === true) {
            $value .= '; preload';
        }

        return $value;
    }

    private function maxAge(): int
    {
        $maxAge = $this->config['max_age'] ?? null;

        if ((is_int($maxAge) || is_string($maxAge)) && ctype_digit((string) $maxAge) && (int) $maxAge > 0) {
            return (int) $maxAge;
        }

        return self::DEFAULT_MAX_AGE;
    }
}
