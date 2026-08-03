<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Coop\CoopCompiler;
use Estin92\SecurityHeaders\Exceptions\InvalidCoop;
use Estin92\SecurityHeaders\Exceptions\InvalidHeaderValue;
use Estin92\SecurityHeaders\Headers\Coop;
use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;
use Estin92\SecurityHeaders\Reporting\ReportToDestination;

function coopDestination(): ReportToDestination
{
    return ReportToDestination::fromTargets(
        ReportingEndpoint::fromConfig('coop', ['url' => 'https://a.example.com/coop']),
        null,
    );
}

test('enforce serialises each value with no reporting', function (string $value) {
    expect((new CoopCompiler)->compileEnforce($value, null))->toBe($value);
})->with([
    'unsafe-none' => [Coop::UnsafeNone->value],
    'same-origin' => [Coop::SameOrigin->value],
    'same-origin-allow-popups' => [Coop::SameOriginAllowPopups->value],
    'noopener-allow-popups' => [Coop::NoopenerAllowPopups->value],
]);

test('enforce appends a quoted report-to when reporting is given', function (string $value) {
    expect((new CoopCompiler)->compileEnforce($value, coopDestination()))
        ->toBe("{$value}; report-to=\"coop\"");
})->with([
    'same-origin' => [Coop::SameOrigin->value],
    'noopener-allow-popups' => [Coop::NoopenerAllowPopups->value],
]);

test('enforce allows unsafe-none with reporting (COOP does not reject it)', function () {
    expect((new CoopCompiler)->compileEnforce(Coop::UnsafeNone->value, coopDestination()))
        ->toBe('unsafe-none; report-to="coop"');
});

test('enforce rejects a non-enum string', function () {
    expect(fn () => (new CoopCompiler)->compileEnforce('bogus', null))
        ->toThrow(InvalidHeaderValue::class);
});

test('enforce rejects a malformed non-string value without a TypeError', function (mixed $value) {
    expect(fn () => (new CoopCompiler)->compileEnforce($value, null))
        ->toThrow(InvalidHeaderValue::class);
})->with([
    'array' => [['same-origin']],
    'boolean' => [true],
    'integer' => [1],
]);

test('report-only serialises the two report-only values with a destination', function (string $value) {
    expect((new CoopCompiler)->compileReportOnly($value, coopDestination()))
        ->toBe("{$value}; report-to=\"coop\"");
})->with([
    'same-origin' => [Coop::SameOrigin->value],
    'same-origin-allow-popups' => [Coop::SameOriginAllowPopups->value],
]);

test('report-only allows unsafe-none with a destination', function () {
    expect((new CoopCompiler)->compileReportOnly(Coop::UnsafeNone->value, coopDestination()))
        ->toBe('unsafe-none; report-to="coop"');
});

test('report-only rejects noopener-allow-popups', function () {
    expect(fn () => (new CoopCompiler)->compileReportOnly(Coop::NoopenerAllowPopups->value, coopDestination()))
        ->toThrow(InvalidCoop::class);
});

test('report-only rejects a non-enum string', function () {
    expect(fn () => (new CoopCompiler)->compileReportOnly('bogus', coopDestination()))
        ->toThrow(InvalidHeaderValue::class);
});

test('report-only rejects a malformed non-string value without a TypeError', function (mixed $value) {
    expect(fn () => (new CoopCompiler)->compileReportOnly($value, coopDestination()))
        ->toThrow(InvalidHeaderValue::class);
})->with([
    'array' => [['same-origin']],
    'boolean' => [true],
    'integer' => [1],
]);

test('a value carrying a header-splitting sequence is rejected', function (string $value) {
    expect(fn () => (new CoopCompiler)->compileEnforce($value, null))
        ->toThrow(InvalidHeaderValue::class);
})->with([
    'crlf' => ["same-origin\r\nInjected: value"],
    'bare lf' => ["same-origin\n"],
]);
