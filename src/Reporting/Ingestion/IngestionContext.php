<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use DateTimeImmutable;

final readonly class IngestionContext
{
    public function __construct(
        public ?string $clientIp,
        public ?string $requestUserAgent,
        public DateTimeImmutable $receivedAt,
    ) {}
}
