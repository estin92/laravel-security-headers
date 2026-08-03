<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

final readonly class IngestionResult
{
    private function __construct(
        public int $status,
        public ?string $errorCode,
    ) {}

    public static function accepted(): self
    {
        return new self(204, null);
    }

    public static function rejected(RejectionReason $reason): self
    {
        return new self($reason->status(), $reason->value);
    }

    public static function serviceUnavailable(): self
    {
        return new self(503, 'service_unavailable');
    }

    public function isAccepted(): bool
    {
        return $this->errorCode === null;
    }
}
