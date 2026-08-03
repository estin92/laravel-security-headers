<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\Events;

final readonly class ReportPruneFailed
{
    /**
     * @param  class-string  $exceptionClass
     */
    public function __construct(
        public PrunePhase $phase,
        public string $exceptionClass,
    ) {}
}
