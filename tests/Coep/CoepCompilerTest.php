<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Coep\CoepCompiler;
use Estin92\SecurityHeaders\Coep\CoepReporting;
use Estin92\SecurityHeaders\Exceptions\InvalidCoep;
use Estin92\SecurityHeaders\Exceptions\InvalidHeaderValue;
use Estin92\SecurityHeaders\Headers\Coep;
use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;

function coepReporting(): CoepReporting
{
    return CoepReporting::fromTargets(
        ReportingEndpoint::fromConfig('coep', ['url' => 'https://a.example.com/coep']),
        null,
    );
}

test('it serialises each value with no reporting', function (string $value) {
    expect((new CoepCompiler)->compile($value))->toBe($value);
})->with([
    'unsafe-none' => [Coep::UnsafeNone->value],
    'require-corp' => [Coep::RequireCorp->value],
    'credentialless' => [Coep::Credentialless->value],
]);

test('it appends a quoted report-to parameter when reporting is given', function (string $value) {
    expect((new CoepCompiler)->compile($value, coepReporting()))
        ->toBe("{$value}; report-to=\"coep\"");
})->with([
    'require-corp' => [Coep::RequireCorp->value],
    'credentialless' => [Coep::Credentialless->value],
]);

test('it rejects unsafe-none paired with reporting', function () {
    expect(fn () => (new CoepCompiler)->compile(Coep::UnsafeNone->value, coepReporting()))
        ->toThrow(InvalidCoep::class);
});

test('it rejects a value outside the Coep enum', function (mixed $value) {
    expect(fn () => (new CoepCompiler)->compile($value))
        ->toThrow(InvalidHeaderValue::class);
})->with([
    'unknown token' => ['require-cors'],
    'empty' => [''],
    'non-string' => [123],
    'uppercase' => ['REQUIRE-CORP'],
]);
