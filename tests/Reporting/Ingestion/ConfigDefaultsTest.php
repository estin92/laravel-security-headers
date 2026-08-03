<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;

test('ingestion is disabled by default', function () {
    expect(config('security-headers.reporting.ingestion.enabled'))->toBeFalse();
});

test('the default report type enum points at the package enum', function () {
    expect(config('security-headers.reporting.ingestion.report_type_enum'))
        ->toBe(ReportType::class);
});

test('the default sanitizer set matches the privacy-conscious posture', function () {
    $sanitizers = config('security-headers.reporting.ingestion.storage.sanitizers');

    expect($sanitizers['remove_client_ip'])->toBeTrue();
    expect($sanitizers['strip_query'])->toBeTrue();
    expect($sanitizers['remove_nel_headers'])->toBeTrue();
    expect($sanitizers['mask_client_ip'])->toBeFalse();
    expect($sanitizers['remove_sample'])->toBeFalse();
    expect($sanitizers['remove_request_user_agent'])->toBeFalse();
    expect($sanitizers['remove_reported_user_agent'])->toBeFalse();
});

test('the default storage mode is sanitized', function () {
    expect(config('security-headers.reporting.ingestion.storage.mode'))->toBe('sanitized');
});

test('the numeric limit defaults match the specification', function () {
    $limits = config('security-headers.reporting.ingestion.limits');

    expect($limits['max_bytes'])->toBe(65536);
    expect($limits['max_reports_per_batch'])->toBe(100);
    expect($limits['json_depth'])->toBe(32);
    expect($limits['url_length'])->toBe(8192);
    expect($limits['user_agent_length'])->toBe(1024);
});

test('the rate-limit defaults are protocol-separated', function () {
    $rate = config('security-headers.reporting.ingestion.rate_limiting');

    expect($rate['enabled'])->toBeTrue();
    expect($rate['limiter'])->toBe('security-headers-ingestion');
    expect($rate['reporting_api_per_minute'])->toBe(120);
    expect($rate['legacy_csp_per_minute'])->toBe(600);
});

test('the retention defaults bound age and row count', function () {
    $retention = config('security-headers.reporting.ingestion.retention');

    expect($retention['days'])->toBe(30);
    expect($retention['max_rows'])->toBe(100000);
});

test('the route defaults expose the collector path', function () {
    expect(config('security-headers.reporting.ingestion.route.path'))->toBe('/security/reports');
    expect(config('security-headers.reporting.ingestion.route.domain'))->toBeNull();
});

test('the database defaults name the reports table', function () {
    expect(config('security-headers.reporting.ingestion.database.table'))->toBe('security_reports');
    expect(config('security-headers.reporting.ingestion.database.connection'))->toBeNull();
});

test('adding the ingestion block leaves the existing emission keys intact', function () {
    expect(config('security-headers.reporting'))->toHaveKeys([
        'endpoints',
        'report_to_groups',
        'ingestion',
    ]);

    expect(config('security-headers.reporting.endpoints'))->toBe([]);
    expect(config('security-headers.reporting.report_to_groups'))->toBe([]);
});
