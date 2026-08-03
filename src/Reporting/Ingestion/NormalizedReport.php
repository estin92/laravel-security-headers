<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use BackedEnum;
use Estin92\SecurityHeaders\Support\JsonObject;

final readonly class NormalizedReport
{
    public function __construct(
        public ReportTypeContract&BackedEnum $type,
        public ?string $url,
        public ?int $age,
        public ?string $reportedUserAgent,
        public ?JsonObject $body,
        public ReportProtocol $protocol,
    ) {}
}
