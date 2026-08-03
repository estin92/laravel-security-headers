<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidReportToDestination;
use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;
use Estin92\SecurityHeaders\Reporting\ReportToDestination;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;

function destinationModern(): ReportingEndpoint
{
    return ReportingEndpoint::fromConfig('security', ['url' => 'https://a.example.com/modern']);
}

function destinationLegacy(string $name = 'security', int $maxAge = 100): ReportToGroup
{
    return ReportToGroup::fromConfig($name, ['max_age' => $maxAge, 'endpoints' => [['endpoint' => 'e']]], ['e' => ['url' => 'https://a.example.com/e']]);
}

test('modern-only exposes the endpoint name', function () {
    expect(ReportToDestination::fromTargets(destinationModern(), null)->reportTo)->toBe('security');
});

test('legacy-only exposes the group name', function () {
    expect(ReportToDestination::fromTargets(null, destinationLegacy())->reportTo)->toBe('security');
});

test('dual same-name is accepted', function () {
    expect(ReportToDestination::fromTargets(destinationModern(), destinationLegacy())->reportTo)->toBe('security');
});

test('it rejects a name mismatch', function () {
    expect(fn () => ReportToDestination::fromTargets(destinationModern(), destinationLegacy('other')))
        ->toThrow(InvalidReportToDestination::class);
});

test('it rejects a removal group', function () {
    expect(fn () => ReportToDestination::fromTargets(null, destinationLegacy('security', 0)))
        ->toThrow(InvalidReportToDestination::class);
});

test('it rejects a removal group even when a modern endpoint is present', function () {
    expect(fn () => ReportToDestination::fromTargets(destinationModern(), destinationLegacy('security', 0)))
        ->toThrow(InvalidReportToDestination::class);
});

test('it rejects two null targets', function () {
    expect(fn () => ReportToDestination::fromTargets(null, null))
        ->toThrow(InvalidReportToDestination::class);
});
