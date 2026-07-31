<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\ReportToCompiler;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;

function compilerRegistry(): array
{
    return [
        'primary' => ['url' => 'https://a.example.com/primary', 'legacy_url' => 'https://a.example.com/legacy'],
        'fallback' => ['url' => 'https://b.example.com/fallback'],
    ];
}

test('it serialises one group with a single endpoint using the legacy url', function () {
    $group = ReportToGroup::fromConfig('security', ['max_age' => 100, 'endpoints' => ['primary']], compilerRegistry());

    expect((new ReportToCompiler)->compile(['security' => $group]))
        ->toBe('{"group":"security","max_age":100,"endpoints":[{"url":"https://a.example.com/legacy"}]}');
});

test('it includes include_subdomains only when set', function () {
    $group = ReportToGroup::fromConfig('g', ['max_age' => 100, 'include_subdomains' => true, 'endpoints' => ['fallback']], compilerRegistry());

    expect((new ReportToCompiler)->compile(['g' => $group]))
        ->toBe('{"group":"g","max_age":100,"include_subdomains":true,"endpoints":[{"url":"https://b.example.com/fallback"}]}');
});

test('it emits priority and weight only when set', function () {
    $group = ReportToGroup::fromConfig('g', [
        'max_age' => 100,
        'endpoints' => [['endpoint' => 'fallback', 'priority' => 2, 'weight' => 1]],
    ], compilerRegistry());

    expect((new ReportToCompiler)->compile(['g' => $group]))
        ->toBe('{"group":"g","max_age":100,"endpoints":[{"url":"https://b.example.com/fallback","priority":2,"weight":1}]}');
});

test('it serialises multiple groups comma-separated in insertion order', function () {
    $a = ReportToGroup::fromConfig('a', ['max_age' => 100, 'endpoints' => ['fallback']], compilerRegistry());
    $b = ReportToGroup::fromConfig('b', ['max_age' => 200, 'endpoints' => ['fallback']], compilerRegistry());

    expect((new ReportToCompiler)->compile(['a' => $a, 'b' => $b]))
        ->toBe('{"group":"a","max_age":100,"endpoints":[{"url":"https://b.example.com/fallback"}]}, {"group":"b","max_age":200,"endpoints":[{"url":"https://b.example.com/fallback"}]}');
});

test('a removal group serialises with max_age 0 and its endpoints', function () {
    $group = ReportToGroup::fromConfig('retire', ['group' => 'old', 'max_age' => 0, 'endpoints' => ['fallback']], compilerRegistry());

    expect((new ReportToCompiler)->compile(['retire' => $group]))
        ->toBe('{"group":"old","max_age":0,"endpoints":[{"url":"https://b.example.com/fallback"}]}');
});

test('an empty set compiles to an empty string', function () {
    expect((new ReportToCompiler)->compile([]))->toBe('');
});
