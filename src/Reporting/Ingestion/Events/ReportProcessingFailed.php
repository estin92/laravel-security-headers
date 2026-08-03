<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\Events;

use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;

final readonly class ReportProcessingFailed
{
    /**
     * @param  class-string  $exceptionClass
     */
    public function __construct(
        public ?ReportProtocol $protocol,
        public ProcessingStage $stage,
        public ?int $batchSize,
        public string $exceptionClass,
    ) {}
}
