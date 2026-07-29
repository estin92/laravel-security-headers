<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Headers;

class SimpleHeaders
{
    /**
     * @var array<string, string>
     */
    private const NAMES = [
        'x_frame_options' => 'X-Frame-Options',
        'x_content_type_options' => 'X-Content-Type-Options',
        'referrer_policy' => 'Referrer-Policy',
        'x_xss_protection' => 'X-XSS-Protection',
    ];

    /**
     * @param  array<mixed>  $headers  Unvalidated config; only known string keys are read.
     */
    public function __construct(private readonly array $headers) {}

    /**
     * @return array<string, string>
     */
    public function compile(): array
    {
        $compiled = [];

        foreach (self::NAMES as $key => $name) {
            $header = $this->headers[$key] ?? null;

            if (! is_array($header) || ($header['enabled'] ?? false) !== true) {
                continue;
            }

            $value = $header['value'] ?? null;

            if (is_string($value)) {
                $compiled[$name] = $value;
            }
        }

        return $compiled;
    }
}
