<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\Events;

final readonly class IngestionStorageUnavailable
{
    public function __construct(public string $table) {}
}
