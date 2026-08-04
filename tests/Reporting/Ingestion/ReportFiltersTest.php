<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Http\Viewer\ReportFilters;
use Estin92\SecurityHeaders\Http\Viewer\ViewerApiException;
use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Support\JsonObject;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function makeFilterReport(array $overrides = []): SecurityReport
{
    return SecurityReport::query()->create(array_merge([
        'type' => 'csp-violation',
        'protocol' => 'reporting-api',
        'url' => 'https://example.com/p',
        'url_origin' => 'https://example.com',
        'age' => 12,
        'reported_user_agent' => 'reported-UA',
        'request_user_agent' => 'request-UA',
        'client_ip' => null,
        'body' => JsonObject::fromNative((object) ['blockedURL' => 'https://evil.example/x']),
        'storage_mode' => 'sanitized',
        'sanitizer_version' => '1:'.str_repeat('a', 64),
        'sanitization_actions' => [],
        'incident_fingerprint' => str_repeat('a', 64),
        'received_at' => '2026-08-03 00:00:00',
    ], $overrides));
}

test('an unknown filter key is rejected, not ignored', function () {
    (new ReportFilters)->applyTo(SecurityReport::query(), ['nonsense' => 'x']);
})->throws(ViewerApiException::class);

test('an array filter value is rejected', function () {
    (new ReportFilters)->applyTo(SecurityReport::query(), ['type' => ['a', 'b']]);
})->throws(ViewerApiException::class);

test('an over-long url_origin is rejected', function () {
    (new ReportFilters)->applyTo(SecurityReport::query(), ['url_origin' => str_repeat('a', 10_000)]);
})->throws(ViewerApiException::class);

test('type and protocol filter to exact matches', function () {
    makeFilterReport(['type' => 'csp-violation', 'protocol' => 'reporting-api']);
    $nel = makeFilterReport(['type' => 'network-error', 'protocol' => 'reporting-api']);

    $ids = (new ReportFilters)->applyTo(SecurityReport::query(), ['type' => 'network-error'])->pluck('id')->all();

    expect($ids)->toBe([$nel->id]);
});

test('the lower boundary is inclusive and the upper boundary is exclusive, in UTC', function () {
    $before = makeFilterReport(['received_at' => '2026-07-31 23:59:59']);
    $lower = makeFilterReport(['received_at' => '2026-08-01 00:00:00']);
    $inside = makeFilterReport(['received_at' => '2026-08-01 12:00:00']);
    $upper = makeFilterReport(['received_at' => '2026-08-02 00:00:00']);

    $ids = (new ReportFilters)->applyTo(SecurityReport::query(), [
        'received_from' => '2026-08-01T00:00:00Z',
        'received_to' => '2026-08-02T00:00:00Z',
    ])->pluck('id')->all();

    expect($ids)->toContain($lower->id, $inside->id);
    expect($ids)->not->toContain($before->id, $upper->id);
});

test('an offset date is normalized to UTC before the boundary compare', function () {
    $justBefore = makeFilterReport(['received_at' => '2026-07-31 23:29:59']);
    $atBound = makeFilterReport(['received_at' => '2026-07-31 23:30:00']);

    $ids = (new ReportFilters)->applyTo(SecurityReport::query(), [
        'received_from' => '2026-08-01T00:30:00+01:00',
        'received_to' => '2026-08-02T00:00:00Z',
    ])->pluck('id')->all();

    expect($ids)->not->toContain($justBefore->id);
    expect($ids)->toContain($atBound->id);
});

test('a non-iso date is rejected', function () {
    (new ReportFilters)->applyTo(SecurityReport::query(), ['received_from' => 'not-a-date']);
})->throws(ViewerApiException::class);
