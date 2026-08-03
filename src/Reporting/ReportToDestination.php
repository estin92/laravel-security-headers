<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting;

use Estin92\SecurityHeaders\Exceptions\InvalidReportToDestination;

final readonly class ReportToDestination
{
    private function __construct(
        public string $reportTo,
    ) {}

    public static function fromTargets(?ReportingEndpoint $modern, ?ReportToGroup $legacy): self
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

        return new self($modern !== null ? $modern->name : $legacy->group);
    }
}
