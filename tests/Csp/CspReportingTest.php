<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Csp\CspReporting;
use Estin92\SecurityHeaders\Exceptions\InvalidReportToDestination;
use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;

function cspModernEndpoint(): ReportingEndpoint
{
    return ReportingEndpoint::fromConfig('security', ['url' => 'https://a.example.com/modern', 'legacy_url' => 'https://a.example.com/legacy']);
}

function cspLegacyGroup(string $name = 'security', int $maxAge = 100): ReportToGroup
{
    return ReportToGroup::fromConfig($name, ['max_age' => $maxAge, 'endpoints' => [['endpoint' => 'e']]], ['e' => ['url' => 'https://a.example.com/e']]);
}

test('modern-only exposes the endpoint name and a report-uri when asked', function () {
    $reporting = CspReporting::fromTargets(cspModernEndpoint(), null, true);

    expect($reporting->reportTo)->toBe('security');
    expect($reporting->reportUri)->toBe('https://a.example.com/legacy');
});

test('modern-only omits report-uri when not asked', function () {
    expect(CspReporting::fromTargets(cspModernEndpoint(), null, false)->reportUri)->toBeNull();
});

test('legacy-only exposes the group name and never a report-uri', function () {
    $reporting = CspReporting::fromTargets(null, cspLegacyGroup(), true);

    expect($reporting->reportTo)->toBe('security');
    expect($reporting->reportUri)->toBeNull();
});

test('dual registration with the same name is accepted', function () {
    expect(CspReporting::fromTargets(cspModernEndpoint(), cspLegacyGroup(), true)->reportTo)->toBe('security');
});

test('it rejects dual targets whose names differ', function () {
    expect(fn () => CspReporting::fromTargets(cspModernEndpoint(), cspLegacyGroup('other'), true))
        ->toThrow(InvalidReportToDestination::class);
});

test('it rejects a removal group as a target', function () {
    expect(fn () => CspReporting::fromTargets(null, cspLegacyGroup('security', 0), false))
        ->toThrow(InvalidReportToDestination::class);
});

test('it rejects a removal group even when a modern endpoint is present', function () {
    expect(fn () => CspReporting::fromTargets(cspModernEndpoint(), cspLegacyGroup('security', 0), true))
        ->toThrow(InvalidReportToDestination::class);
});

test('it rejects two null targets', function () {
    expect(fn () => CspReporting::fromTargets(null, null, false))
        ->toThrow(InvalidReportToDestination::class);
});
