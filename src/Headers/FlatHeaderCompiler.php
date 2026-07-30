<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Headers;

use Estin92\SecurityHeaders\Exceptions\InvalidHeaderValue;

class FlatHeaderCompiler
{
    /**
     * @var array<string, array{name: string, values: class-string<\BackedEnum>}>
     */
    private const HEADERS = [
        'x_frame_options' => [
            'name' => 'X-Frame-Options',
            'values' => XFrameOptions::class,
        ],

        'x_content_type_options' => [
            'name' => 'X-Content-Type-Options',
            'values' => XContentTypeOptions::class,
        ],

        'referrer_policy' => [
            'name' => 'Referrer-Policy',
            'values' => ReferrerPolicy::class,
        ],

        'x_xss_protection' => [
            'name' => 'X-XSS-Protection',
            'values' => XssProtection::class,
        ],

        'cross_origin_opener_policy' => [
            'name' => 'Cross-Origin-Opener-Policy',
            'values' => Coop::class,
        ],

        'cross_origin_resource_policy' => [
            'name' => 'Cross-Origin-Resource-Policy',
            'values' => Corp::class,
        ],

        'cross_origin_embedder_policy' => [
            'name' => 'Cross-Origin-Embedder-Policy',
            'values' => Coep::class,
        ],
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

        foreach (self::HEADERS as $key => $definition) {
            $header = $this->headers[$key] ?? null;

            if (! is_array($header) || ($header['enabled'] ?? false) !== true) {
                continue;
            }

            $value = $header['value'] ?? null;

            if (is_string($value)) {
                $this->guardValue($key, $definition, $value);

                $compiled[$definition['name']] = $value;
            }
        }

        return $compiled;
    }

    /**
     * @param  array{name: string, values: class-string<\BackedEnum>}  $definition
     */
    private function guardValue(string $key, array $definition, string $value): void
    {
        $name = $definition['name'];

        if (preg_match('/[\x00-\x1f\x7f]/', $value) === 1) {
            throw InvalidHeaderValue::containsControlCharacters($name, $value);
        }

        $enum = $definition['values'];

        $valid = $key === 'referrer_policy'
            ? $this->isTokenList($enum, $value)
            : $enum::tryFrom($value) !== null;

        if (! $valid) {
            throw InvalidHeaderValue::notInValueSet($name, $value);
        }
    }

    /**
     * @param  class-string<\BackedEnum>  $enum
     */
    private function isTokenList(string $enum, string $value): bool
    {
        $tokens = array_map('trim', explode(',', $value));

        foreach ($tokens as $token) {
            if ($enum::tryFrom($token) === null) {
                return false;
            }
        }

        return true;
    }
}
