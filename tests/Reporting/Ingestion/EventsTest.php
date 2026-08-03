<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ProcessingStage;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReceivedSecurityReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportPersistenceFailed;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportProcessingFailed;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportSubmissionRejected;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\SecurityReportsReceived;
use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Estin92\SecurityHeaders\Reporting\Ingestion\StorageMode;

function received(int $id = 1): ReceivedSecurityReport
{
    return new ReceivedSecurityReport(
        $id,
        'csp-violation',
        ReportProtocol::ReportingApi,
        'https://example.com',
        str_repeat('a', 64),
        StorageMode::Sanitized,
    );
}

test('a received report carries only safe, derived fields', function () {
    $event = received(7);

    expect($event->id)->toBe(7);
    expect($event->type)->toBe('csp-violation');
    expect($event->protocol)->toBe(ReportProtocol::ReportingApi);
    expect($event->origin)->toBe('https://example.com');
    expect($event->incidentFingerprint)->toBe(str_repeat('a', 64));
    expect($event->storageMode)->toBe(StorageMode::Sanitized);
});

test('the batch event exposes its reports and their count', function () {
    $event = new SecurityReportsReceived([received(1), received(2)]);

    expect($event->reports)->toHaveCount(2);
    expect($event->count())->toBe(2);
});

test('the batch event rejects an empty list', function () {
    expect(fn () => new SecurityReportsReceived([]))
        ->toThrow(InvalidArgumentException::class);
});

test('a rejection event carries the reason, status and optional context', function () {
    $event = new ReportSubmissionRejected(
        ReportProtocol::ReportingApi,
        RejectionReason::UnacceptedReportType,
        422,
        3,
        'unheard-of',
    );

    expect($event->protocol)->toBe(ReportProtocol::ReportingApi);
    expect($event->reason)->toBe(RejectionReason::UnacceptedReportType);
    expect($event->status)->toBe(422);
    expect($event->batchSize)->toBe(3);
    expect($event->offendingType)->toBe('unheard-of');
});

test('a rejection event allows unknown batch size and type', function () {
    $event = new ReportSubmissionRejected(
        null,
        RejectionReason::MalformedJson,
        400,
        null,
        null,
    );

    expect($event->batchSize)->toBeNull();
    expect($event->offendingType)->toBeNull();
});

test('a processing failure carries a stage and the exception class only', function () {
    $event = new ReportProcessingFailed(
        ReportProtocol::ReportingApi,
        ProcessingStage::ConsumerValidation,
        2,
        RuntimeException::class,
    );

    expect($event->stage)->toBe(ProcessingStage::ConsumerValidation);
    expect($event->exceptionClass)->toBe(RuntimeException::class);
});

test('a persistence failure carries the exception class only', function () {
    $event = new ReportPersistenceFailed(ReportProtocol::ReportingApi, 2, RuntimeException::class);

    expect($event->exceptionClass)->toBe(RuntimeException::class);
    expect($event->batchSize)->toBe(2);
});

test('no event carries report content', function () {
    $properties = [
        ...array_keys(get_object_vars(received())),
        ...array_keys(get_object_vars(new ReportSubmissionRejected(null, RejectionReason::MalformedJson, 400, null, null))),
        ...array_keys(get_object_vars(new ReportProcessingFailed(ReportProtocol::ReportingApi, ProcessingStage::ConsumerValidation, 1, RuntimeException::class))),
    ];

    foreach (['body', 'url', 'clientIp', 'ip', 'userAgent', 'message'] as $forbidden) {
        expect($properties)->not->toContain($forbidden);
    }
});
