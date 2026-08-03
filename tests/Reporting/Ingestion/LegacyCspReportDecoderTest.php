<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidReportSubmission;
use Estin92\SecurityHeaders\Reporting\Ingestion\LegacyCspReportDecoder;
use Estin92\SecurityHeaders\Reporting\Ingestion\NormalizedReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeResolver;
use Estin92\SecurityHeaders\Support\JsonObject;
use Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures\CoopOnlyReportType;

function legacyDecoder(array $overrides = []): LegacyCspReportDecoder
{
    $limits = array_merge([
        'max_bytes' => 65536,
        'json_depth' => 32,
    ], $overrides);

    return new LegacyCspReportDecoder(ReportTypeResolver::forEnum(ReportType::class), $limits);
}

function legacyReport(array $report): string
{
    return json_encode(['csp-report' => $report]);
}

function legacyReason(callable $fn): RejectionReason
{
    try {
        $fn();
    } catch (InvalidReportSubmission $e) {
        return $e->reason;
    }

    throw new RuntimeException('Expected InvalidReportSubmission, none thrown.');
}

test('a legacy report decodes to one CSP violation', function () {
    $report = legacyDecoder()->decode(legacyReport([
        'document-uri' => 'https://example.com/page',
        'blocked-uri' => 'https://evil.example/x',
        'effective-directive' => 'script-src',
    ]));

    expect($report)->toBeInstanceOf(NormalizedReport::class);
    expect($report->type)->toBe(ReportType::CspViolation);
    expect($report->protocol)->toBe(ReportProtocol::LegacyCspReportUri);
    expect($report->body)->toBeInstanceOf(JsonObject::class);
});

test('every specified legacy key maps to its canonical name', function () {
    $report = legacyDecoder()->decode(legacyReport([
        'document-uri' => 'https://example.com/page',
        'blocked-uri' => 'https://evil.example/x',
        'effective-directive' => 'script-src',
        'original-policy' => "default-src 'self'",
        'source-file' => 'https://example.com/app.js',
        'script-sample' => 'alert(1)',
        'status-code' => 200,
        'line-number' => 42,
        'column-number' => 7,
    ]));

    $body = $report->body;
    expect($body->get(['documentURL']))->toBe('https://example.com/page');
    expect($body->get(['blockedURL']))->toBe('https://evil.example/x');
    expect($body->get(['effectiveDirective']))->toBe('script-src');
    expect($body->get(['originalPolicy']))->toBe("default-src 'self'");
    expect($body->get(['sourceFile']))->toBe('https://example.com/app.js');
    expect($body->get(['sample']))->toBe('alert(1)');
    expect($body->get(['statusCode']))->toBe(200);
    expect($body->get(['lineNumber']))->toBe(42);
    expect($body->get(['columnNumber']))->toBe(7);
});

test('keys that already match are kept as they are', function () {
    $report = legacyDecoder()->decode(legacyReport([
        'effective-directive' => 'script-src',
        'referrer' => 'https://example.com/',
        'disposition' => 'enforce',
    ]));

    expect($report->body->get(['referrer']))->toBe('https://example.com/');
    expect($report->body->get(['disposition']))->toBe('enforce');
});

test('violated-directive and effective-directive with the same value collapse to one', function () {
    $report = legacyDecoder()->decode(legacyReport([
        'violated-directive' => 'script-src',
        'effective-directive' => 'script-src',
    ]));

    expect($report->body->get(['effectiveDirective']))->toBe('script-src');
    expect($report->body->has(['violatedDirective']))->toBeFalse();
});

test('violated-directive alone maps to effectiveDirective', function () {
    $report = legacyDecoder()->decode(legacyReport([
        'violated-directive' => 'script-src',
    ]));

    expect($report->body->get(['effectiveDirective']))->toBe('script-src');
});

test('violated-directive and effective-directive with different values collide', function () {
    expect(legacyReason(fn () => legacyDecoder()->decode(legacyReport([
        'violated-directive' => 'script-src',
        'effective-directive' => 'style-src',
    ]))))->toBe(RejectionReason::InvalidField);
});

test('unknown legacy keys are preserved unchanged', function () {
    $report = legacyDecoder()->decode(legacyReport([
        'effective-directive' => 'script-src',
        'some-future-field' => 'kept',
    ]));

    expect($report->body->get(['some-future-field']))->toBe('kept');
});

test('CSP keywords like inline and eval are kept as they are', function (string $blocked) {
    $report = legacyDecoder()->decode(legacyReport([
        'effective-directive' => 'script-src',
        'blocked-uri' => $blocked,
    ]));

    expect($report->body->get(['blockedURL']))->toBe($blocked);
})->with([
    'inline' => ['inline'],
    'eval' => ['eval'],
    'data' => ['data'],
    'empty' => [''],
]);

test('a body with no csp-report wrapper is a malformed envelope', function () {
    expect(legacyReason(fn () => legacyDecoder()->decode('{"effective-directive":"script-src"}')))
        ->toBe(RejectionReason::InvalidEnvelope);
});

test('a csp-report that is not an object is a malformed envelope', function (mixed $inner) {
    expect(legacyReason(fn () => legacyDecoder()->decode(json_encode(['csp-report' => $inner]))))
        ->toBe(RejectionReason::InvalidEnvelope);
})->with([
    'list' => [[1, 2, 3]],
    'string' => ['a string'],
    'null' => [null],
]);

test('a top-level array is a malformed envelope', function () {
    expect(legacyReason(fn () => legacyDecoder()->decode('[]')))
        ->toBe(RejectionReason::InvalidEnvelope);
});

test('a body over the byte cap is rejected', function () {
    $raw = legacyReport(['effective-directive' => 'script-src']);

    expect(legacyReason(fn () => legacyDecoder(['max_bytes' => 10])->decode($raw)))
        ->toBe(RejectionReason::RequestTooLarge);
});

test('json nested past the depth limit is malformed json', function () {
    $raw = legacyReport(['effective-directive' => 'script-src', 'nested' => ['a' => ['b' => 1]]]);

    expect(legacyReason(fn () => legacyDecoder(['json_depth' => 3])->decode($raw)))
        ->toBe(RejectionReason::MalformedJson);
});

test('syntactically broken json is malformed json', function () {
    expect(legacyReason(fn () => legacyDecoder()->decode('{"csp-report":')))
        ->toBe(RejectionReason::MalformedJson);
});

test('an installation whose enum drops csp-violation still rejects it', function () {
    $resolver = ReportTypeResolver::forEnum(
        CoopOnlyReportType::class,
    );
    $decoder = new LegacyCspReportDecoder($resolver, ['max_bytes' => 65536, 'json_depth' => 32]);

    expect(legacyReason(fn () => $decoder->decode(legacyReport(['effective-directive' => 'script-src']))))
        ->toBe(RejectionReason::UnacceptedReportType);
});
