<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidReportBody;
use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\BodyValidatorRegistry;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\CspBodyValidator;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\ReportBodyValidator;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportPersistenceFailed;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportProcessingFailed;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportSubmissionRejected;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\SecurityReportsReceived;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionContext;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionPipeline;
use Estin92\SecurityHeaders\Reporting\Ingestion\LegacyCspReportDecoder;
use Estin92\SecurityHeaders\Reporting\Ingestion\ModernReportDecoder;
use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeResolver;
use Estin92\SecurityHeaders\Reporting\Ingestion\StoragePolicy;
use Estin92\SecurityHeaders\Support\JsonObject;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Psr\Log\LoggerInterface;

uses(RefreshDatabase::class);

function pipeline(?Dispatcher $events = null): IngestionPipeline
{
    $limits = [
        'max_bytes' => 65536,
        'max_reports_per_batch' => 100,
        'json_depth' => 32,
        'url_length' => 8192,
        'user_agent_length' => 1024,
    ];
    $resolver = ReportTypeResolver::forEnum(ReportType::class);
    $storageConfig = [
        'storage' => [
            'mode' => 'sanitized',
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
    ];

    return new IngestionPipeline(
        new ModernReportDecoder($resolver, $limits),
        new LegacyCspReportDecoder($resolver, ['max_bytes' => 65536, 'json_depth' => 32]),
        new BodyValidatorRegistry([], app()),
        new StoragePolicy($storageConfig),
        $events ?? app(Dispatcher::class),
        DB::connection(),
        app(LoggerInterface::class),
    );
}

function ingestionContext(): IngestionContext
{
    return new IngestionContext('203.0.113.9', 'req-UA', new DateTimeImmutable('2026-08-03T00:00:00Z'));
}

function modernBatch(int $count = 1): string
{
    $entries = [];
    for ($i = 0; $i < $count; $i++) {
        $entries[] = [
            'type' => 'csp-violation',
            'age' => 10,
            'url' => 'https://example.com/p?token=abc',
            'user_agent' => 'Mozilla/5.0',
            'body' => ['blockedURL' => 'https://evil.example/x'],
        ];
    }

    return json_encode($entries, JSON_THROW_ON_ERROR);
}

test('a modern batch persists every report in one go and returns 204', function () {
    Event::fake([SecurityReportsReceived::class]);

    $result = pipeline()->ingest('application/reports+json', modernBatch(2), ingestionContext());

    expect($result->status)->toBe(204);
    expect($result->isAccepted())->toBeTrue();
    expect(SecurityReport::query()->count())->toBe(2);
    Event::assertDispatched(SecurityReportsReceived::class, fn ($e) => $e->count() === 2);
});

test('an unsupported media type is rejected with 415', function () {
    Event::fake([ReportSubmissionRejected::class]);

    $result = pipeline()->ingest('text/plain', modernBatch(), ingestionContext());

    expect($result->status)->toBe(415);
    expect(SecurityReport::query()->count())->toBe(0);
    Event::assertDispatched(ReportSubmissionRejected::class);
});

test('an empty modern batch returns 204 with no rows and no event', function () {
    Event::fake([SecurityReportsReceived::class]);

    $result = pipeline()->ingest('application/reports+json', '[]', ingestionContext());

    expect($result->status)->toBe(204);
    expect(SecurityReport::query()->count())->toBe(0);
    Event::assertNotDispatched(SecurityReportsReceived::class);
});

test('malformed json is rejected with 400', function () {
    Event::fake([ReportSubmissionRejected::class]);

    $result = pipeline()->ingest('application/reports+json', '[{', ingestionContext());

    expect($result->status)->toBe(400);
    expect(SecurityReport::query()->count())->toBe(0);
});

test('an unaccepted type rejects the whole batch with 422 and stores nothing', function () {
    Event::fake([ReportSubmissionRejected::class]);
    $batch = json_encode([
        ['type' => 'csp-violation', 'age' => 1, 'url' => 'https://x', 'user_agent' => 'UA', 'body' => null],
        ['type' => 'unheard-of', 'age' => 1, 'url' => 'https://x', 'user_agent' => 'UA', 'body' => null],
    ], JSON_THROW_ON_ERROR);

    $result = pipeline()->ingest('application/reports+json', $batch, ingestionContext());

    expect($result->status)->toBe(422);
    expect(SecurityReport::query()->count())->toBe(0);
    Event::assertDispatched(
        ReportSubmissionRejected::class,
        fn ($e) => $e->reason === RejectionReason::UnacceptedReportType && $e->offendingType === 'unheard-of',
    );
});

test('a throwing listener does not undo the commit and still returns 204', function () {
    $events = app(Dispatcher::class);
    $events->listen(SecurityReportsReceived::class, function () {
        throw new RuntimeException('listener blew up');
    });

    $result = pipeline($events)->ingest('application/reports+json', modernBatch(), ingestionContext());

    expect($result->status)->toBe(204);
    expect(SecurityReport::query()->count())->toBe(1);
});

test('the batch event is discarded when an outer transaction rolls back', function () {
    Event::fake([SecurityReportsReceived::class]);

    try {
        DB::transaction(function () {
            pipeline()->ingest('application/reports+json', modernBatch(), ingestionContext());

            throw new RuntimeException('roll the outer back');
        });
    } catch (RuntimeException) {
        // expected
    }

    expect(SecurityReport::query()->count())->toBe(0);
    Event::assertNotDispatched(SecurityReportsReceived::class);
});

test('a database failure rolls back, dispatches ReportPersistenceFailed and returns 503', function () {
    Event::fake([ReportPersistenceFailed::class, SecurityReportsReceived::class]);
    Schema::drop('security_reports');

    $result = pipeline()->ingest('application/reports+json', modernBatch(2), ingestionContext());

    expect($result->status)->toBe(503);
    Event::assertDispatched(ReportPersistenceFailed::class);
    Event::assertNotDispatched(SecurityReportsReceived::class);
});

test('a legacy CSP report is decoded and persisted through the pipeline', function () {
    Event::fake([SecurityReportsReceived::class]);
    $raw = json_encode(['csp-report' => ['effective-directive' => 'script-src', 'blocked-uri' => 'https://evil.example/x']], JSON_THROW_ON_ERROR);

    $result = pipeline()->ingest('application/csp-report', $raw, ingestionContext());

    expect($result->status)->toBe(204);
    expect(SecurityReport::query()->where('protocol', 'legacy-csp-report-uri')->count())->toBe(1);
    Event::assertDispatched(SecurityReportsReceived::class);
});

test('a validator rejecting the body with InvalidReportBody is a 422', function () {
    Event::fake([ReportSubmissionRejected::class, SecurityReportsReceived::class]);
    app()->bind(
        CspBodyValidator::class,
        fn () => new class implements ReportBodyValidator
        {
            public function validate(?JsonObject $body): void
            {
                throw InvalidReportBody::forType('csp-violation');
            }
        },
    );

    $result = pipeline()->ingest('application/reports+json', modernBatch(), ingestionContext());

    expect($result->status)->toBe(422);
    expect(SecurityReport::query()->count())->toBe(0);
    Event::assertDispatched(ReportSubmissionRejected::class);
    Event::assertNotDispatched(SecurityReportsReceived::class);
});

test('a consumer validator throwing an unexpected exception is a 503 processing failure', function () {
    Event::fake([ReportProcessingFailed::class]);
    app()->bind(
        CspBodyValidator::class,
        fn () => new class implements ReportBodyValidator
        {
            public function validate(?JsonObject $body): void
            {
                throw new RuntimeException('consumer validator bug');
            }
        },
    );

    $result = pipeline()->ingest('application/reports+json', modernBatch(), ingestionContext());

    expect($result->status)->toBe(503);
    expect(SecurityReport::query()->count())->toBe(0);
    Event::assertDispatched(ReportProcessingFailed::class, fn ($e) => $e->stage->value === 'consumer_validation');
});
