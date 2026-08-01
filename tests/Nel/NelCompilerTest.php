<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidNel;
use Estin92\SecurityHeaders\Nel\NelCompiler;
use Estin92\SecurityHeaders\Nel\NelPolicy;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;

function compilerGroup(): ReportToGroup
{
    return ReportToGroup::fromConfig('network-errors', ['max_age' => 2592000, 'endpoints' => ['e']], ['e' => ['url' => 'https://a.example.com/e']]);
}

function positivePolicy(array $overrides = []): NelPolicy
{
    return NelPolicy::fromConfig(array_merge(['report_to_group' => 'network-errors', 'max_age' => 2592000], $overrides));
}

test('a minimal positive policy emits report_to and max_age only', function () {
    expect((new NelCompiler)->compile(positivePolicy(), compilerGroup()))
        ->toBe('{"report_to":"network-errors","max_age":2592000}');
});

test('include_subdomains is emitted only when true', function () {
    expect((new NelCompiler)->compile(positivePolicy(['include_subdomains' => true]), compilerGroup()))
        ->toBe('{"report_to":"network-errors","max_age":2592000,"include_subdomains":true}');
});

test('include_subdomains false is omitted', function () {
    expect((new NelCompiler)->compile(positivePolicy(['include_subdomains' => false]), compilerGroup()))
        ->toBe('{"report_to":"network-errors","max_age":2592000}');
});

test('fractions are emitted only when non-default', function () {
    expect((new NelCompiler)->compile(positivePolicy(['success_fraction' => 0.5, 'failure_fraction' => 0.25]), compilerGroup()))
        ->toBe('{"report_to":"network-errors","max_age":2592000,"success_fraction":0.5,"failure_fraction":0.25}');
});

test('a null fraction and an explicit default fraction serialise identically', function () {
    $absent = (new NelCompiler)->compile(positivePolicy(), compilerGroup());
    $explicitDefault = (new NelCompiler)->compile(positivePolicy(['success_fraction' => 0.0, 'failure_fraction' => 1.0]), compilerGroup());

    expect($explicitDefault)->toBe($absent);
    expect($explicitDefault)->not->toContain('success_fraction');
    expect($explicitDefault)->not->toContain('failure_fraction');
});

test('non-default whole-value fractions serialise as bare integers', function () {
    expect((new NelCompiler)->compile(positivePolicy(['success_fraction' => 1.0, 'failure_fraction' => 0.0]), compilerGroup()))
        ->toBe('{"report_to":"network-errors","max_age":2592000,"success_fraction":1,"failure_fraction":0}');
});

test('all optional fields together serialise in a deterministic order', function () {
    expect((new NelCompiler)->compile(positivePolicy(['include_subdomains' => true, 'success_fraction' => 0.5, 'failure_fraction' => 0.9]), compilerGroup()))
        ->toBe('{"report_to":"network-errors","max_age":2592000,"include_subdomains":true,"success_fraction":0.5,"failure_fraction":0.9}');
});

test('a non-default failure_fraction alone is emitted', function () {
    expect((new NelCompiler)->compile(positivePolicy(['failure_fraction' => 0.5]), compilerGroup()))
        ->toBe('{"report_to":"network-errors","max_age":2592000,"failure_fraction":0.5}');
});

test('the emitted header decodes to the intended values', function () {
    $header = (new NelCompiler)->compile(positivePolicy(['success_fraction' => 1.0]), compilerGroup());
    $decoded = json_decode($header, true);

    expect($decoded['report_to'])->toBe('network-errors');
    expect($decoded['max_age'])->toBe(2592000);
    expect($decoded['success_fraction'])->toBe(1);
});

test('a removal serialises to max_age zero only', function () {
    $removal = NelPolicy::fromConfig(['max_age' => 0]);

    expect((new NelCompiler)->compile($removal, null))->toBe('{"max_age":0}');
});

test('it rejects a positive policy with no group', function () {
    expect(fn () => (new NelCompiler)->compile(positivePolicy(), null))
        ->toThrow(InvalidNel::class);
});

test('it rejects a removal policy paired with a group', function () {
    $removal = NelPolicy::fromConfig(['max_age' => 0]);

    expect(fn () => (new NelCompiler)->compile($removal, compilerGroup()))
        ->toThrow(InvalidNel::class);
});
