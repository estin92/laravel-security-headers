<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\Events;

final readonly class ReportsPruned
{
    public function __construct(
        public int $expired,
        public int $excess,
        public int $remaining,
        public float $durationSeconds,
    ) {}
}
