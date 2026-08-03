<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\Events;

use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Estin92\SecurityHeaders\Reporting\Ingestion\StorageMode;

final readonly class ReceivedSecurityReport
{
    public function __construct(
        public int $id,
        public string $type,
        public ReportProtocol $protocol,
        public ?string $origin,
        public string $incidentFingerprint,
        public StorageMode $storageMode,
    ) {}
}
