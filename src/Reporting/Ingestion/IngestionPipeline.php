<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use Estin92\SecurityHeaders\Exceptions\InvalidReportBody;
use Estin92\SecurityHeaders\Exceptions\InvalidReportSubmission;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\BodyValidatorRegistry;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ProcessingStage;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReceivedSecurityReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportPersistenceFailed;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportProcessingFailed;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportSubmissionRejected;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\SecurityReportsReceived;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Connection;
use Psr\Log\LoggerInterface;
use Throwable;

final class IngestionPipeline
{
    public function __construct(
        private readonly ModernReportDecoder $modernDecoder,
        private readonly LegacyCspReportDecoder $legacyDecoder,
        private readonly BodyValidatorRegistry $validators,
        private readonly StoragePolicy $storagePolicy,
        private readonly Dispatcher $events,
        private readonly Connection $connection,
        private readonly LoggerInterface $logger,
    ) {}

    public function ingest(string $contentType, string $raw, IngestionContext $context): IngestionResult
    {
        $protocol = ReportProtocol::fromContentType($contentType);

        if ($protocol === null) {
            return $this->reject(null, RejectionReason::UnsupportedMediaType, null, null);
        }

        try {
            $reports = $this->decode($protocol, $raw);
        } catch (InvalidReportSubmission $e) {
            return $this->reject($protocol, $e->reason, null, $e->offendingType);
        }

        if ($reports === []) {
            return IngestionResult::accepted();
        }

        try {
            $this->validateBodies($reports);
        } catch (InvalidReportBody) {
            return $this->reject($protocol, RejectionReason::InvalidReportBody, count($reports), null);
        } catch (Throwable $e) {
            return $this->processingFailed($protocol, count($reports), $e);
        }

        return $this->persist($protocol, $reports, $context);
    }

    /**
     * @return list<NormalizedReport>
     */
    private function decode(ReportProtocol $protocol, string $raw): array
    {
        if ($protocol === ReportProtocol::LegacyCspReportUri) {
            return [$this->legacyDecoder->decode($raw)];
        }

        return $this->modernDecoder->decode($raw);
    }

    /**
     * @param  list<NormalizedReport>  $reports
     */
    private function validateBodies(array $reports): void
    {
        foreach ($reports as $report) {
            $this->validators->for((string) $report->type->value)->validate($report->body);
        }
    }

    /**
     * @param  list<NormalizedReport>  $reports
     */
    private function persist(ReportProtocol $protocol, array $reports, IngestionContext $context): IngestionResult
    {
        try {
            $this->persistBatch($reports, $context);
        } catch (Throwable $e) {
            $this->events->dispatch(new ReportPersistenceFailed($protocol, count($reports), $e::class));

            return IngestionResult::serviceUnavailable();
        }

        return IngestionResult::accepted();
    }

    /**
     * @param  list<NormalizedReport>  $reports
     * @return list<ReceivedSecurityReport>
     */
    private function persistBatch(array $reports, IngestionContext $context): array
    {
        $summaries = [];

        $this->connection->transaction(function () use ($reports, $context, &$summaries) {
            foreach ($reports as $report) {
                $submission = new ReportSubmission($report, $context->receivedAt, $context->clientIp, $context->requestUserAgent);
                $model = $this->storagePolicy->apply($submission);
                $model->save();

                $summaries[] = new ReceivedSecurityReport(
                    $model->id,
                    $model->type,
                    $report->protocol,
                    $model->url_origin,
                    $model->incident_fingerprint,
                    $model->storage_mode === StorageMode::Raw->value ? StorageMode::Raw : StorageMode::Sanitized,
                );
            }

            $this->connection->afterCommit(function () use ($summaries) {
                try {
                    $this->events->dispatch(new SecurityReportsReceived($summaries));
                } catch (Throwable $e) {
                    $this->logger->error('A security-report listener failed.', ['exception' => $e::class]);
                }
            });
        });

        return $summaries;
    }

    private function reject(?ReportProtocol $protocol, RejectionReason $reason, ?int $batchSize, ?string $offendingType): IngestionResult
    {
        $this->events->dispatch(new ReportSubmissionRejected($protocol, $reason, $reason->status(), $batchSize, $offendingType));

        return IngestionResult::rejected($reason);
    }

    private function processingFailed(ReportProtocol $protocol, int $batchSize, Throwable $e): IngestionResult
    {
        $this->events->dispatch(new ReportProcessingFailed($protocol, ProcessingStage::ConsumerValidation, $batchSize, $e::class));

        return IngestionResult::serviceUnavailable();
    }
}
