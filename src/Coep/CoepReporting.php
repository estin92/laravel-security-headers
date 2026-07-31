<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Coep;

use Estin92\SecurityHeaders\Exceptions\InvalidReportToGroup;
use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;

final readonly class CoepReporting
{
    private function __construct(
        public string $reportTo,
    ) {}

    public static function fromTargets(?ReportingEndpoint $modern, ?ReportToGroup $legacy): self
    {
        if ($legacy !== null && $legacy->isRemoval()) {
            throw InvalidReportToGroup::removalGroupNotAddressable($legacy->group);
        }

        if ($modern !== null && $legacy !== null && $modern->name !== $legacy->group) {
            throw InvalidReportToGroup::targetNameMismatch($modern->name, $legacy->group);
        }

        if ($modern === null && $legacy === null) {
            throw InvalidReportToGroup::noReportingTarget();
        }

        return new self($modern !== null ? $modern->name : $legacy->group);
    }
}
