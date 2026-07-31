<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidReportToGroup;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;

function groupRegistry(): array
{
    return [
        'primary' => ['url' => 'https://a.example.com/primary'],
        'fallback' => ['url' => 'https://a.example.com/fallback'],
    ];
}

test('the emitted name defaults to the registry key', function () {
    $group = ReportToGroup::fromConfig('security', ['max_age' => 100, 'endpoints' => ['primary']], groupRegistry());

    expect($group->group)->toBe('security');
    expect($group->maxAge)->toBe(100);
    expect($group->includeSubdomains)->toBeNull();
    expect($group->endpoints)->toHaveCount(1);
    expect($group->isRemoval())->toBeFalse();
});

test('an explicit group name overrides the key', function () {
    $group = ReportToGroup::fromConfig('retire-old', ['group' => 'old-name', 'max_age' => 0, 'endpoints' => ['primary']], groupRegistry());

    expect($group->group)->toBe('old-name');
    expect($group->isRemoval())->toBeTrue();
});

test('it preserves configured endpoint order', function () {
    $group = ReportToGroup::fromConfig('g', ['max_age' => 100, 'endpoints' => ['fallback', 'primary']], groupRegistry());

    expect($group->endpoints[0]->endpoint->name)->toBe('fallback');
    expect($group->endpoints[1]->endpoint->name)->toBe('primary');
});

test('a canonical integer string max_age is accepted', function () {
    $group = ReportToGroup::fromConfig('g', ['max_age' => '10886400', 'endpoints' => ['primary']], groupRegistry());

    expect($group->maxAge)->toBe(10886400);
});

test('include_subdomains handles booleans and env strings', function (mixed $value, ?bool $expected) {
    $group = ReportToGroup::fromConfig('g', ['max_age' => 100, 'include_subdomains' => $value, 'endpoints' => ['primary']], groupRegistry());

    expect($group->includeSubdomains)->toBe($expected);
})->with([
    'true' => [true, true],
    'false' => [false, false],
    'string true' => ['true', true],
    'string false' => ['false', false],
    'string one' => ['1', true],
    'string zero' => ['0', false],
    'int one' => [1, true],
    'int zero' => [0, false],
    'empty string' => ['', false],
]);

test('it rejects a malformed group definition', function (string $key, mixed $definition) {
    expect(fn () => ReportToGroup::fromConfig($key, $definition, groupRegistry()))
        ->toThrow(InvalidReportToGroup::class);
})->with([
    'non-array definition' => ['g', 'not-an-array'],
    'invalid key grammar' => ['Bad_Key', ['max_age' => 100, 'endpoints' => ['primary']]],
    'invalid key with valid explicit name' => ['Bad_Key', ['group' => 'good-name', 'max_age' => 100, 'endpoints' => ['primary']]],
    'invalid explicit name' => ['g', ['group' => 'Bad Name', 'max_age' => 100, 'endpoints' => ['primary']]],
    'missing max_age' => ['g', ['endpoints' => ['primary']]],
    'decimal max_age' => ['g', ['max_age' => '1.5', 'endpoints' => ['primary']]],
    'exponent max_age' => ['g', ['max_age' => '1e3', 'endpoints' => ['primary']]],
    'padded max_age' => ['g', ['max_age' => ' 100 ', 'endpoints' => ['primary']]],
    'negative max_age' => ['g', ['max_age' => -1, 'endpoints' => ['primary']]],
    'float max_age' => ['g', ['max_age' => 1.0, 'endpoints' => ['primary']]],
    'oversized max_age' => ['g', ['max_age' => '999999999999999999999999', 'endpoints' => ['primary']]],
    'rubbish include_subdomains' => ['g', ['max_age' => 100, 'include_subdomains' => 'rubbish', 'endpoints' => ['primary']]],
    'unknown group key' => ['g', ['max_age' => 100, 'include_subdomain' => true, 'endpoints' => ['primary']]],
    'missing endpoints' => ['g', ['max_age' => 100]],
    'non-array endpoints' => ['g', ['max_age' => 100, 'endpoints' => 'primary']],
    'keyed (non-list) endpoints' => ['g', ['max_age' => 100, 'endpoints' => ['x' => 'primary']]],
    'empty endpoints' => ['g', ['max_age' => 100, 'endpoints' => []]],
    'duplicate endpoints' => ['g', ['max_age' => 100, 'endpoints' => ['primary', 'primary']]],
    'duplicate with differing routing' => ['g', ['max_age' => 100, 'endpoints' => ['primary', ['endpoint' => 'primary', 'priority' => 2]]]],
]);
