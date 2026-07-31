<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidReportToMembership;
use Estin92\SecurityHeaders\Reporting\ReportToEndpoint;

function membershipRegistry(): array
{
    return [
        'primary' => ['url' => 'https://a.example.com/primary'],
        'fallback' => ['url' => 'https://a.example.com/fallback', 'legacy_url' => 'https://a.example.com/legacy'],
    ];
}

test('a shorthand string resolves to an endpoint with no routing', function () {
    $membership = ReportToEndpoint::fromConfig('primary', membershipRegistry());

    expect($membership->endpoint->name)->toBe('primary');
    expect($membership->priority)->toBeNull();
    expect($membership->weight)->toBeNull();
});

test('an expanded entry resolves with priority and weight', function () {
    $membership = ReportToEndpoint::fromConfig(
        ['endpoint' => 'fallback', 'priority' => 2, 'weight' => 1],
        membershipRegistry(),
    );

    expect($membership->endpoint->name)->toBe('fallback');
    expect($membership->priority)->toBe(2);
    expect($membership->weight)->toBe(1);
});

test('a canonical integer string is accepted for routing values', function () {
    $membership = ReportToEndpoint::fromConfig(
        ['endpoint' => 'primary', 'priority' => '1', 'weight' => '3'],
        membershipRegistry(),
    );

    expect($membership->priority)->toBe(1);
    expect($membership->weight)->toBe(3);
});

test('an explicit null routing value is accepted', function () {
    $membership = ReportToEndpoint::fromConfig(
        ['endpoint' => 'primary', 'priority' => null, 'weight' => null],
        membershipRegistry(),
    );

    expect($membership->priority)->toBeNull();
    expect($membership->weight)->toBeNull();
});

test('it rejects a dangling endpoint reference', function () {
    expect(fn () => ReportToEndpoint::fromConfig('ghost', membershipRegistry()))
        ->toThrow(InvalidReportToMembership::class);
});

test('it rejects a malformed membership shape', function (mixed $membership) {
    expect(fn () => ReportToEndpoint::fromConfig($membership, membershipRegistry()))
        ->toThrow(InvalidReportToMembership::class);
})->with([
    'integer' => [123],
    'missing endpoint key' => [['priority' => 1]],
    'non-string endpoint' => [['endpoint' => 123]],
    'unknown key' => [['endpoint' => 'primary', 'priorty' => 1]],
]);

test('it rejects a malformed priority', function (mixed $value) {
    expect(fn () => ReportToEndpoint::fromConfig(['endpoint' => 'primary', 'priority' => $value], membershipRegistry()))
        ->toThrow(InvalidReportToMembership::class);
})->with([
    'decimal' => ['1.5'],
    'float' => [1.0],
    'exponent' => ['1e3'],
    'padded' => [' 1 '],
    'negative' => [-1],
    'non-numeric' => ['high'],
    'oversized string' => ['999999999999999999999999'],
    'boolean' => [true],
]);

test('it rejects a malformed weight', function (mixed $value) {
    expect(fn () => ReportToEndpoint::fromConfig(['endpoint' => 'primary', 'weight' => $value], membershipRegistry()))
        ->toThrow(InvalidReportToMembership::class);
})->with([
    'decimal' => ['1.5'],
    'float' => [1.0],
    'exponent' => ['1e3'],
    'padded' => [' 1 '],
    'negative' => [-1],
    'non-numeric' => ['heavy'],
    'oversized string' => ['999999999999999999999999'],
]);
