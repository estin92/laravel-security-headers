<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use DateTimeImmutable;

final readonly class ReportSubmission
{
    public function __construct(
        public NormalizedReport $report,
        public DateTimeImmutable $receivedAt,
        public ?string $clientIp,
        public ?string $requestUserAgent,
    ) {}
}
