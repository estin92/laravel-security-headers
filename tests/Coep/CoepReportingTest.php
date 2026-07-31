<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Coep\CoepReporting;
use Estin92\SecurityHeaders\Exceptions\InvalidReportToGroup;
use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;

function coepModern(): ReportingEndpoint
{
    return ReportingEndpoint::fromConfig('security', ['url' => 'https://a.example.com/modern']);
}

function coepLegacy(string $name = 'security', int $maxAge = 100): ReportToGroup
{
    return ReportToGroup::fromConfig($name, ['max_age' => $maxAge, 'endpoints' => [['endpoint' => 'e']]], ['e' => ['url' => 'https://a.example.com/e']]);
}

test('modern-only exposes the endpoint name', function () {
    expect(CoepReporting::fromTargets(coepModern(), null)->reportTo)->toBe('security');
});

test('legacy-only exposes the group name', function () {
    expect(CoepReporting::fromTargets(null, coepLegacy())->reportTo)->toBe('security');
});

test('dual same-name is accepted', function () {
    expect(CoepReporting::fromTargets(coepModern(), coepLegacy())->reportTo)->toBe('security');
});

test('it rejects a name mismatch', function () {
    expect(fn () => CoepReporting::fromTargets(coepModern(), coepLegacy('other')))
        ->toThrow(InvalidReportToGroup::class);
});

test('it rejects a removal group', function () {
    expect(fn () => CoepReporting::fromTargets(null, coepLegacy('security', 0)))
        ->toThrow(InvalidReportToGroup::class);
});

test('it rejects a removal group even when a modern endpoint is present', function () {
    expect(fn () => CoepReporting::fromTargets(coepModern(), coepLegacy('security', 0)))
        ->toThrow(InvalidReportToGroup::class);
});

test('it rejects two null targets', function () {
    expect(fn () => CoepReporting::fromTargets(null, null))
        ->toThrow(InvalidReportToGroup::class);
});
