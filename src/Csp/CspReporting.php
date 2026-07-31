<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Csp;

use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;

final readonly class CspReporting
{
    private function __construct(
        public string $reportTo,
        public ?string $reportUri,
    ) {}

    public static function fromEndpoint(ReportingEndpoint $endpoint, bool $emitLegacy): self
    {
        return new self(
            reportTo: $endpoint->name,
            reportUri: $emitLegacy ? $endpoint->reportUri() : null,
        );
    }
}
