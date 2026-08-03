<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures;

use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeContract;

enum IntBackedReportType: int implements ReportTypeContract
{
    case CspViolation = 1;

    public function label(): string
    {
        return 'CSP violation';
    }
}
