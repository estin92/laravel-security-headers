<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting;

use Estin92\SecurityHeaders\Exceptions\InvalidReportToMembership;
use Estin92\SecurityHeaders\Support\NonNegativeInt;

final readonly class ReportToEndpoint
{
    private function __construct(
        public ReportingEndpoint $endpoint,
        public ?int $priority,
        public ?int $weight,
    ) {}

    /**
     * @param  array<mixed>  $endpointRegistry
     */
    public static function fromConfig(mixed $membership, array $endpointRegistry): self
    {
        if (is_string($membership)) {
            $membership = ['endpoint' => $membership];
        }

        if (! is_array($membership) || ! isset($membership['endpoint']) || ! is_string($membership['endpoint'])) {
            throw InvalidReportToMembership::notAnEndpointReference($membership);
        }

        foreach (array_keys($membership) as $key) {
            if (! in_array($key, ['endpoint', 'priority', 'weight'], true)) {
                throw InvalidReportToMembership::unknownMembershipKey((string) $key);
            }
        }

        $name = $membership['endpoint'];

        if (! array_key_exists($name, $endpointRegistry)) {
            throw InvalidReportToMembership::unknownEndpoint($name);
        }

        return new self(
            ReportingEndpoint::fromConfig($name, $endpointRegistry[$name]),
            self::routingValue('priority', $membership['priority'] ?? null),
            self::routingValue('weight', $membership['weight'] ?? null),
        );
    }

    private static function routingValue(string $key, mixed $value): ?int
    {
        if ($value === null) {
            return null;
        }

        return NonNegativeInt::parse($value) ?? throw InvalidReportToMembership::invalidRoutingValue($key, $value);
    }
}
