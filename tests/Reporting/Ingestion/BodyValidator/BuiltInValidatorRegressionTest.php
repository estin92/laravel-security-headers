<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidReportBody;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\CoepBodyValidator;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\CoopBodyValidator;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\NelBodyValidator;
use Estin92\SecurityHeaders\Support\JsonObject;

function regressionBody(string $json): JsonObject
{
    return JsonObject::fromNative(json_decode($json, false, 512, JSON_THROW_ON_ERROR));
}

test('the COEP validator accepts its own reporting disposition', function () {
    (new CoepBodyValidator)->validate(regressionBody('{"disposition":"reporting"}'));
})->throwsNoExceptions();

test('the COEP validator rejects the CSP disposition wording', function () {
    expect(fn () => (new CoepBodyValidator)->validate(regressionBody('{"disposition":"report"}')))
        ->toThrow(InvalidReportBody::class);
});

test('the COOP validator treats disposition as a free string, not a finite set', function (string $value) {
    (new CoopBodyValidator)->validate(regressionBody(json_encode(['disposition' => $value], JSON_THROW_ON_ERROR)));
})->throwsNoExceptions()->with(['enforce', 'reporting', 'anything-goes-here']);

test('the NEL validator rejects a negative status code', function () {
    expect(fn () => (new NelBodyValidator)->validate(regressionBody('{"status_code":-5}')))
        ->toThrow(InvalidReportBody::class);
});

test('the NEL validator accepts a fully-populated well-formed body', function () {
    (new NelBodyValidator)->validate(regressionBody(json_encode([
        'type' => 'http.error',
        'server_ip' => '203.0.113.9',
        'protocol' => 'h2',
        'referrer' => 'https://x/p',
        'method' => 'GET',
        'phase' => 'application',
        'sampling_fraction' => 0.5,
        'elapsed_time' => 12,
        'status_code' => 500,
        'request_headers' => ['accept' => 'text/html'],
        'response_headers' => ['server' => ['nginx', 'cf']],
    ], JSON_THROW_ON_ERROR)));
})->throwsNoExceptions();
