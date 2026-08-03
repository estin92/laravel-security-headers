<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\NormalizedReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportSubmission;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Reporting\Ingestion\StoragePolicy;
use Estin92\SecurityHeaders\SecurityHeadersServiceProvider;
use Estin92\SecurityHeaders\Support\JsonObject;

function storageConfig(array $overrides = []): array
{
    return array_replace_recursive([
        'storage' => [
            'mode' => 'sanitized',
            'raw_acknowledged' => false,
            'sanitizers' => [
                'remove_client_ip' => true,
                'mask_client_ip' => false,
                'strip_query' => true,
                'remove_sample' => false,
                'remove_nel_headers' => true,
                'remove_request_user_agent' => false,
                'remove_reported_user_agent' => false,
            ],
        ],
    ], $overrides);
}

function policySubmission(
    ?string $url = 'https://example.com/p?token=abc',
    ?JsonObject $body = null,
    string $clientIp = '203.0.113.9',
): ReportSubmission {
    $report = new NormalizedReport(
        ReportType::CspViolation,
        $url,
        12,
        'reported-UA',
        $body ?? JsonObject::fromNative((object) ['blockedURL' => 'https://evil.example/x?s=1']),
        ReportProtocol::ReportingApi,
    );

    return new ReportSubmission($report, new DateTimeImmutable('2026-08-03T00:00:00Z'), $clientIp, 'request-UA');
}

test('it builds an unsaved report with the sanitized values', function () {
    $report = (new StoragePolicy(storageConfig()))->apply(policySubmission());

    expect($report)->toBeInstanceOf(SecurityReport::class);
    expect($report->exists)->toBeFalse();
    expect($report->url)->toBe('https://example.com/p');
    expect($report->client_ip)->toBeNull();
    expect($report->body->get(['blockedURL']))->toBe('https://evil.example/x');
});

test('it derives url_origin from the persisted url', function () {
    $report = (new StoragePolicy(storageConfig()))->apply(policySubmission());

    expect($report->url_origin)->toBe('https://example.com');
});

test('a null persisted url gives a null origin and a different fingerprint', function () {
    $config = storageConfig();
    $withUrl = (new StoragePolicy($config))->apply(policySubmission(url: 'https://a.example/p'));
    $noUrl = (new StoragePolicy($config))->apply(policySubmission(url: null));

    expect($noUrl->url_origin)->toBeNull();
    expect($noUrl->incident_fingerprint)->not->toBe($withUrl->incident_fingerprint);
});

test('the sanitizer version is the package version plus a 64-hex config hash', function () {
    $report = (new StoragePolicy(storageConfig()))->apply(policySubmission());

    expect($report->sanitizer_version)->toMatch('/\A'.preg_quote(SecurityHeadersServiceProvider::VERSION, '/').':[0-9a-f]{64}\z/');
});

test('the sanitizer version is stable across config key reordering', function () {
    $ordered = storageConfig();
    $reordered = storageConfig();
    $reordered['storage']['sanitizers'] = array_reverse($reordered['storage']['sanitizers'], true);

    $a = (new StoragePolicy($ordered))->apply(policySubmission());
    $b = (new StoragePolicy($reordered))->apply(policySubmission());

    expect($a->sanitizer_version)->toBe($b->sanitizer_version);
});

test('changing a toggle changes the sanitizer version', function () {
    $default = (new StoragePolicy(storageConfig()))->apply(policySubmission());
    $masked = (new StoragePolicy(storageConfig(['storage' => ['sanitizers' => ['remove_client_ip' => false, 'mask_client_ip' => true]]])))->apply(policySubmission());

    expect($default->sanitizer_version)->not->toBe($masked->sanitizer_version);
});

test('raw mode marks the version as raw and records no actions', function () {
    $config = storageConfig(['storage' => ['mode' => 'raw', 'raw_acknowledged' => true]]);
    $report = (new StoragePolicy($config))->apply(policySubmission());

    expect($report->storage_mode)->toBe('raw');
    expect($report->sanitizer_version)->toBe(SecurityHeadersServiceProvider::VERSION.':raw');
    expect($report->sanitization_actions)->toBe([]);
    expect($report->client_ip)->toBe('203.0.113.9');
    expect($report->url)->toBe('https://example.com/p?token=abc');
});

test('the persisted row carries the normalized envelope fields', function () {
    $report = (new StoragePolicy(storageConfig()))->apply(policySubmission());

    expect($report->type)->toBe('csp-violation');
    expect($report->protocol)->toBe('reporting-api');
    expect($report->age)->toBe(12);
    expect($report->reported_user_agent)->toBe('reported-UA');
    expect($report->received_at->toDateTimeString())->toBe('2026-08-03 00:00:00');
});

test('the incident fingerprint is a lowercase 64-hex string', function () {
    $report = (new StoragePolicy(storageConfig()))->apply(policySubmission());

    expect($report->incident_fingerprint)->toMatch('/\A[0-9a-f]{64}\z/');
});
