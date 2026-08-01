<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidNel;
use Estin92\SecurityHeaders\Nel\NelPolicy;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;

function nelGroup(int $maxAge = 2592000, ?bool $includeSubdomains = null): ReportToGroup
{
    $definition = ['max_age' => $maxAge, 'endpoints' => ['e']];

    if ($includeSubdomains !== null) {
        $definition['include_subdomains'] = $includeSubdomains;
    }

    return ReportToGroup::fromConfig('network-errors', $definition, ['e' => ['url' => 'https://a.example.com/e']]);
}

test('a positive policy resolves all fields', function () {
    $policy = NelPolicy::fromConfig([
        'report_to_group' => 'network-errors',
        'max_age' => 2592000,
        'include_subdomains' => true,
        'success_fraction' => 0.5,
        'failure_fraction' => 0.9,
    ]);

    expect($policy->reportToGroupKey)->toBe('network-errors');
    expect($policy->maxAge)->toBe(2592000);
    expect($policy->includeSubdomains)->toBeTrue();
    expect($policy->successFraction)->toBe(0.5);
    expect($policy->failureFraction)->toBe(0.9);
    expect($policy->isRemoval())->toBeFalse();
});

test('a minimal positive policy defaults optional fields to null', function () {
    $policy = NelPolicy::fromConfig(['report_to_group' => 'network-errors', 'max_age' => 100]);

    expect($policy->includeSubdomains)->toBeNull();
    expect($policy->successFraction)->toBeNull();
    expect($policy->failureFraction)->toBeNull();
});

test('a removal policy carries only max_age zero', function (mixed $maxAge) {
    $policy = NelPolicy::fromConfig(['max_age' => $maxAge]);

    expect($policy->isRemoval())->toBeTrue();
    expect($policy->reportToGroupKey)->toBeNull();
})->with([
    'int zero' => [0],
    'string zero' => ['0'],
]);

test('a removal accepts optional fields left at their defaults', function (array $definition) {
    expect(NelPolicy::fromConfig($definition)->isRemoval())->toBeTrue();
})->with([
    'nulls' => [['max_age' => 0, 'report_to_group' => null, 'include_subdomains' => null, 'success_fraction' => null, 'failure_fraction' => null]],
    'effective defaults' => [['max_age' => 0, 'include_subdomains' => false, 'success_fraction' => 0.0, 'failure_fraction' => 1.0]],
    'env default booleans' => [['max_age' => 0, 'include_subdomains' => 'false']],
]);

test('the published env-driven removal validates clean', function () {
    $policy = NelPolicy::fromConfig([
        'report_to_group' => null,
        'max_age' => '0',
        'include_subdomains' => false,
        'success_fraction' => null,
        'failure_fraction' => null,
    ]);

    expect($policy->isRemoval())->toBeTrue();
});

test('a canonical .env max_age string is accepted', function () {
    expect(NelPolicy::fromConfig(['report_to_group' => 'g', 'max_age' => '2592000'])->maxAge)->toBe(2592000);
});

test('include_subdomains accepts the full FILTER_VALIDATE_BOOL set (matching ReportToGroup)', function (mixed $value, ?bool $expected) {
    $policy = NelPolicy::fromConfig(['report_to_group' => 'g', 'max_age' => 100, 'include_subdomains' => $value]);

    expect($policy->includeSubdomains)->toBe($expected);
})->with([
    'true' => [true, true],
    'false' => [false, false],
    'native int one' => [1, true],
    'native int zero' => [0, false],
    'string true' => ['true', true],
    'string false' => ['false', false],
    'string one' => ['1', true],
    'string zero' => ['0', false],
    'yes' => ['yes', true],
    'no' => ['no', false],
    'on' => ['on', true],
    'off' => ['off', false],
    'empty string' => ['', false],
]);

test('it rejects a malformed policy definition', function (mixed $definition) {
    expect(fn () => NelPolicy::fromConfig($definition))->toThrow(InvalidNel::class);
})->with([
    'non-array' => ['not-an-array'],
    'unknown key' => [['report_to_group' => 'g', 'max_age' => 100, 'enabled' => true]],
    'missing max_age' => [['report_to_group' => 'g']],
    'decimal max_age' => [['report_to_group' => 'g', 'max_age' => '1.5']],
    'exponent max_age' => [['report_to_group' => 'g', 'max_age' => '1e3']],
    'padded max_age' => [['report_to_group' => 'g', 'max_age' => ' 1 ']],
    'negative max_age' => [['report_to_group' => 'g', 'max_age' => -1]],
    'float max_age' => [['report_to_group' => 'g', 'max_age' => 1.0]],
    'oversized max_age' => [['report_to_group' => 'g', 'max_age' => '999999999999999999999999']],
    'bool max_age' => [['report_to_group' => 'g', 'max_age' => true]],
    'positive missing report_to_group' => [['max_age' => 100]],
    'positive empty report_to_group' => [['report_to_group' => '', 'max_age' => 100]],
    'positive non-string report_to_group' => [['report_to_group' => ['x'], 'max_age' => 100]],
    'rubbish include_subdomains' => [['report_to_group' => 'g', 'max_age' => 100, 'include_subdomains' => 'rubbish']],
    'out-of-range success_fraction' => [['report_to_group' => 'g', 'max_age' => 100, 'success_fraction' => 1.5]],
    'non-numeric success_fraction' => [['report_to_group' => 'g', 'max_age' => 100, 'success_fraction' => 'abc']],
    'out-of-range failure_fraction' => [['report_to_group' => 'g', 'max_age' => 100, 'failure_fraction' => -0.1]],
    'exponent failure_fraction' => [['report_to_group' => 'g', 'max_age' => 100, 'failure_fraction' => '5e-1']],
]);

test('a removal with a non-default value is rejected', function (array $definition) {
    expect(fn () => NelPolicy::fromConfig($definition))->toThrow(InvalidNel::class);
})->with([
    'report_to_group set' => [['max_age' => 0, 'report_to_group' => 'network-errors']],
    'report_to_group non-string' => [['max_age' => 0, 'report_to_group' => ['x']]],
    'report_to_group empty string' => [['max_age' => 0, 'report_to_group' => '']],
    'include_subdomains true' => [['max_age' => 0, 'include_subdomains' => true]],
    'include_subdomains string true' => [['max_age' => 0, 'include_subdomains' => '1']],
    'success_fraction non-default' => [['max_age' => 0, 'success_fraction' => 0.5]],
    'failure_fraction non-default' => [['max_age' => 0, 'failure_fraction' => 0.5]],
]);

test('a removal with a malformed optional value reports the malformed error, not the removal error', function () {
    expect(fn () => NelPolicy::fromConfig(['max_age' => 0, 'include_subdomains' => 'rubbish']))
        ->toThrow(InvalidNel::class, 'include_subdomains must be a boolean');
    expect(fn () => NelPolicy::fromConfig(['max_age' => 0, 'success_fraction' => '1.5']))
        ->toThrow(InvalidNel::class, 'success_fraction must be a number');
});

test('assertCompatibleWith passes for a compatible group', function () {
    $policy = NelPolicy::fromConfig(['report_to_group' => 'network-errors', 'max_age' => 100, 'include_subdomains' => true]);

    $policy->assertCompatibleWith(nelGroup(maxAge: 100, includeSubdomains: true));

    expect(true)->toBeTrue();
});

test('assertCompatibleWith accepts an equal group lifetime', function () {
    $policy = NelPolicy::fromConfig(['report_to_group' => 'g', 'max_age' => 100]);

    $policy->assertCompatibleWith(nelGroup(maxAge: 100));

    expect(true)->toBeTrue();
});

test('assertCompatibleWith rejects a removal group', function () {
    $policy = NelPolicy::fromConfig(['report_to_group' => 'g', 'max_age' => 100]);

    expect(fn () => $policy->assertCompatibleWith(nelGroup(maxAge: 0)))
        ->toThrow(InvalidNel::class);
});

test('assertCompatibleWith rejects a group whose lifetime is too short', function () {
    $policy = NelPolicy::fromConfig(['report_to_group' => 'g', 'max_age' => 200]);

    expect(fn () => $policy->assertCompatibleWith(nelGroup(maxAge: 100)))
        ->toThrow(InvalidNel::class);
});

test('assertCompatibleWith rejects a group that does not cover subdomains', function (?bool $groupSubdomains) {
    $policy = NelPolicy::fromConfig(['report_to_group' => 'g', 'max_age' => 100, 'include_subdomains' => true]);

    expect(fn () => $policy->assertCompatibleWith(nelGroup(maxAge: 100, includeSubdomains: $groupSubdomains)))
        ->toThrow(InvalidNel::class);
})->with([
    'group null' => [null],
    'group false' => [false],
]);
