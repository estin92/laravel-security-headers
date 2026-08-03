<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Console\PruneReportsCommand;
use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\PrunePhase;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportPruneFailed;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportsPruned;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

beforeEach(function () {
    $this->app[Kernel::class]->registerCommand(new PruneReportsCommand);
});

function seedReport(string $receivedAt): SecurityReport
{
    return SecurityReport::query()->create([
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

test('it deletes rows older than the retention window and keeps the rest', function () {
    config()->set('security-headers.reporting.ingestion.retention.days', 30);
    config()->set('security-headers.reporting.ingestion.retention.max_rows', 100000);

    $old = seedReport(now()->subDays(40)->toDateTimeString());
    $fresh = seedReport(now()->subDays(5)->toDateTimeString());

    $this->artisan('security-headers:prune-reports')->assertSuccessful();

    expect(SecurityReport::query()->find($old->id))->toBeNull();
    expect(SecurityReport::query()->find($fresh->id))->not->toBeNull();
});

test('it trims the oldest rows beyond max_rows', function () {
    config()->set('security-headers.reporting.ingestion.retention.days', 30);
    config()->set('security-headers.reporting.ingestion.retention.max_rows', 2);

    $oldest = seedReport(now()->subDays(3)->toDateTimeString());
    $middle = seedReport(now()->subDays(2)->toDateTimeString());
    $newest = seedReport(now()->subDays(1)->toDateTimeString());

    $this->artisan('security-headers:prune-reports')->assertSuccessful();

    expect(SecurityReport::query()->find($oldest->id))->toBeNull();
    expect(SecurityReport::query()->find($middle->id))->not->toBeNull();
    expect(SecurityReport::query()->find($newest->id))->not->toBeNull();
});

test('a successful prune dispatches ReportsPruned with the counts', function () {
    Event::fake([ReportsPruned::class]);
    config()->set('security-headers.reporting.ingestion.retention.days', 30);
    config()->set('security-headers.reporting.ingestion.retention.max_rows', 1);

    seedReport(now()->subDays(40)->toDateTimeString());
    seedReport(now()->subDays(3)->toDateTimeString());
    seedReport(now()->subDays(2)->toDateTimeString());

    $this->artisan('security-headers:prune-reports')->assertSuccessful();

    Event::assertDispatched(
        ReportsPruned::class,
        fn ($e) => $e->expired === 1 && $e->excess === 1 && $e->remaining === 1,
    );
});

test('a prune failure dispatches ReportPruneFailed and exits non-zero', function () {
    Event::fake([ReportPruneFailed::class]);
    config()->set('security-headers.reporting.ingestion.retention.days', 30);
    Schema::drop('security_reports');

    $this->artisan('security-headers:prune-reports')->assertFailed();

    Event::assertDispatched(ReportPruneFailed::class);
});

test('the prune events carry no report content', function () {
    $pruned = new ReportsPruned(1, 2, 3, 0.5);
    $failed = new ReportPruneFailed(
        PrunePhase::Expired,
        RuntimeException::class,
    );

    foreach (['body', 'url', 'clientIp', 'message'] as $forbidden) {
        expect(array_keys(get_object_vars($pruned)))->not->toContain($forbidden);
        expect(array_keys(get_object_vars($failed)))->not->toContain($forbidden);
    }
});
