<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Console\AuditCommand;
use Estin92\SecurityHeaders\Models\SecurityReport;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

beforeEach(function () {
    $this->app[Kernel::class]->registerCommand(new AuditCommand);
});

function seedAuditReport(string $receivedAt): void
{
    SecurityReport::query()->create([
        'type' => 'csp-violation',
        'protocol' => 'reporting-api',
        'url' => 'https://example.com/p',
        'url_origin' => 'https://example.com',
        'age' => 1,
        'body' => null,
        'storage_mode' => 'sanitized',
        'sanitizer_version' => '0.1.0:'.str_repeat('a', 64),
        'sanitization_actions' => [],
        'incident_fingerprint' => str_repeat('a', 64),
        'received_at' => $receivedAt,
    ]);
}

test('a clean configuration passes with a zero exit', function () {
    $this->artisan('security-headers:audit')
        ->assertSuccessful();
});

test('a missing table is a hard finding that fails the audit', function () {
    Schema::drop('security_reports');

    $this->artisan('security-headers:audit')
        ->expectsOutputToContain('table')
        ->assertFailed();
});

test('an invalid configuration is a hard finding that fails the audit', function () {
    config()->set('security-headers.reporting.ingestion.retention.days', 0);

    $this->artisan('security-headers:audit')
        ->assertFailed();
});

test('invalid retention config skips retention analysis instead of querying with a default', function () {
    config()->set('security-headers.reporting.ingestion.retention.days', 0);
    seedAuditReport(now()->subDays(40)->toDateTimeString());

    $this->artisan('security-headers:audit')
        ->expectsOutputToContain('Retention configuration is invalid')
        ->doesntExpectOutputToContain('no current retention violation')
        ->assertFailed();
});

test('raw mode without acknowledgement warns but does not fail', function () {
    config()->set('security-headers.reporting.ingestion.storage.mode', 'raw');
    config()->set('security-headers.reporting.ingestion.storage.raw_acknowledged', false);

    $this->artisan('security-headers:audit')
        ->expectsOutputToContain('raw')
        ->assertSuccessful();
});

test('raw mode with acknowledgement is silent', function () {
    config()->set('security-headers.reporting.ingestion.storage.mode', 'raw');
    config()->set('security-headers.reporting.ingestion.storage.raw_acknowledged', true);

    $this->artisan('security-headers:audit')
        ->doesntExpectOutputToContain('raw')
        ->assertSuccessful();
});

test('rate limiting disabled without acknowledgement warns but does not fail', function () {
    config()->set('security-headers.reporting.ingestion.rate_limiting.enabled', false);
    config()->set('security-headers.reporting.ingestion.rate_limiting.external_limiting_acknowledged', false);

    $this->artisan('security-headers:audit')
        ->expectsOutputToContain('rate limiting')
        ->assertSuccessful();
});

test('rate limiting disabled with acknowledgement is silent', function () {
    config()->set('security-headers.reporting.ingestion.rate_limiting.enabled', false);
    config()->set('security-headers.reporting.ingestion.rate_limiting.external_limiting_acknowledged', true);

    $this->artisan('security-headers:audit')
        ->doesntExpectOutputToContain('rate limiting')
        ->assertSuccessful();
});

test('expired rows still present warn but do not fail', function () {
    config()->set('security-headers.reporting.ingestion.retention.days', 30);
    seedAuditReport(now()->subDays(40)->toDateTimeString());

    $this->artisan('security-headers:audit')
        ->expectsOutputToContain('retention')
        ->assertSuccessful();
});

test('no expired rows reports no current retention violation, not health', function () {
    config()->set('security-headers.reporting.ingestion.retention.days', 30);
    seedAuditReport(now()->subDays(5)->toDateTimeString());

    $this->artisan('security-headers:audit')
        ->expectsOutputToContain('no current retention violation')
        ->assertSuccessful();
});
