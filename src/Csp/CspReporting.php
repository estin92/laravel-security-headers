<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Csp;

use Estin92\SecurityHeaders\Exceptions\InvalidReportToDestination;
use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;

final readonly class CspReporting
{
    private function __construct(
        public string $reportTo,
        public ?string $reportUri,
    ) {}

    public static function fromTargets(?ReportingEndpoint $modern, ?ReportToGroup $legacy, bool $emitReportUri): self
    {
        if ($legacy !== null && $legacy->isRemoval()) {
            throw InvalidReportToDestination::removalGroupNotAddressable($legacy->group);
        }

        if ($modern !== null && $legacy !== null && $modern->name !== $legacy->group) {
            throw InvalidReportToDestination::targetNameMismatch($modern->name, $legacy->group);
        }

        if ($modern === null && $legacy === null) {
            throw InvalidReportToDestination::noTarget();
        }

        return new self(
            $modern !== null ? $modern->name : $legacy->group,
            $modern !== null && $emitReportUri ? $modern->reportUri() : null,
        );
    }
}
