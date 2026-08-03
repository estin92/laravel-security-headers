<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures;

use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeContract;

enum UnbackedReportType implements ReportTypeContract
{
    case CspViolation;

    public function label(): string
    {
        return 'CSP violation';
    }
}
