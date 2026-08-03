<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\Ingestion\NormalizedReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportSubmission;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Support\JsonObject;

test('a normalized report carries the resolved type and body', function () {
    $body = JsonObject::fromNative(json_decode('{"a":1}', false));
    $r = new NormalizedReport(ReportType::CspViolation, 'https://x', 12, 'UA', $body, ReportProtocol::ReportingApi);

    expect($r->type)->toBe(ReportType::CspViolation);
    expect($r->url)->toBe('https://x');
    expect($r->body)->toBe($body);
});

test('a submission wraps the report with ingestion context', function () {
    $r = new NormalizedReport(ReportType::Coop, null, null, null, null, ReportProtocol::LegacyCspReportUri);
    $at = new DateTimeImmutable('2026-08-03T00:00:00Z');
    $s = new ReportSubmission($r, $at, '203.0.113.9', 'req-UA');

    expect($s->report)->toBe($r);
    expect($s->receivedAt)->toBe($at);
    expect($s->clientIp)->toBe('203.0.113.9');
    expect($s->requestUserAgent)->toBe('req-UA');
});

test('a normalized report is immutable', function () {
    $r = new NormalizedReport(ReportType::Coep, null, null, null, null, ReportProtocol::ReportingApi);

    expect(fn () => $r->url = 'x')->toThrow(Error::class);
});
