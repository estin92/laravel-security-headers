<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\Events;

use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;

final readonly class ReportSubmissionRejected
{
    public function __construct(
        public ?ReportProtocol $protocol,
        public RejectionReason $reason,
        public int $status,
        public ?int $batchSize,
        public ?string $offendingType,
    ) {}
}
