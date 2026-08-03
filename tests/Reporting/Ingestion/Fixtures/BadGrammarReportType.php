<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures;

use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeContract;

enum BadGrammarReportType: string implements ReportTypeContract
{
    case Shouting = 'CSP_Violation';

    public function label(): string
    {
        return 'Shouting';
    }
}
