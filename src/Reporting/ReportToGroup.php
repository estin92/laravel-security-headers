<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting;

use Estin92\SecurityHeaders\Exceptions\InvalidReportToGroup;
use Estin92\SecurityHeaders\Support\NonNegativeInt;

final readonly class ReportToGroup
{
    /**
     * @param  list<ReportToEndpoint>  $endpoints
     */
    private function __construct(
        public string $group,
        public int $maxAge,
        public ?bool $includeSubdomains,
        public array $endpoints,
    ) {}

    /**
     * @param  array<mixed>  $endpointRegistry
     */
    public static function fromConfig(string $key, mixed $definition, array $endpointRegistry): self
    {
        if (! is_array($definition)) {
            throw InvalidReportToGroup::notAnArray($key);
        }

        foreach (array_keys($definition) as $configKey) {
            if (! in_array($configKey, ['group', 'max_age', 'include_subdomains', 'endpoints'], true)) {
                throw InvalidReportToGroup::unknownGroupKey($key, (string) $configKey);
            }
        }

        $name = $definition['group'] ?? $key;

        if (! is_string($name) || ! self::isValidName($name)) {
            throw InvalidReportToGroup::invalidName(is_string($name) ? $name : $key);
        }

        if (! self::isValidName($key)) {
            throw InvalidReportToGroup::invalidName($key);
        }

        return new self(
            $name,
            self::maxAge($name, $definition),
            self::includeSubdomains($name, $definition),
            self::endpoints($name, $definition, $endpointRegistry),
        );
    }

    public function isRemoval(): bool
    {
        return $this->maxAge === 0;
    }

    private static function isValidName(string $value): bool
    {
        return preg_match('/\A[a-z][a-z0-9-]*\z/', $value) === 1;
    }

    /**
     * @param  array<mixed>  $definition
     */
    private static function maxAge(string $group, array $definition): int
    {
        if (! array_key_exists('max_age', $definition)) {
            throw InvalidReportToGroup::missingMaxAge($group);
        }

        $value = $definition['max_age'];

        return NonNegativeInt::parse($value) ?? throw InvalidReportToGroup::invalidMaxAge($group, $value);
    }

    /**
     * @param  array<mixed>  $definition
     */
    private static function includeSubdomains(string $group, array $definition): ?bool
    {
        if (! array_key_exists('include_subdomains', $definition) || $definition['include_subdomains'] === null) {
            return null;
        }

        $value = filter_var($definition['include_subdomains'], FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);

        if ($value === null) {
            throw InvalidReportToGroup::invalidIncludeSubdomains($group, $definition['include_subdomains']);
        }

        return $value;
    }

    /**
     * @param  array<mixed>  $definition
     * @param  array<mixed>  $endpointRegistry
     * @return list<ReportToEndpoint>
     */
    private static function endpoints(string $group, array $definition, array $endpointRegistry): array
    {
        $configured = $definition['endpoints'] ?? null;

        if (! is_array($configured) || ! array_is_list($configured)) {
            throw InvalidReportToGroup::endpointsNotAList($group);
        }

        if ($configured === []) {
            throw InvalidReportToGroup::emptyEndpoints($group);
        }

        $endpoints = [];
        $seen = [];

        foreach ($configured as $membership) {
            $endpoint = ReportToEndpoint::fromConfig($membership, $endpointRegistry);
            $name = $endpoint->endpoint->name;

            if (isset($seen[$name])) {
                throw InvalidReportToGroup::duplicateEndpoint($group, $name);
            }

            $seen[$name] = true;
            $endpoints[] = $endpoint;
        }

        return $endpoints;
    }
}
