<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures;

use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeContract;

enum CoopOnlyReportType: string implements ReportTypeContract
{
    case Coop = 'coop';

    public function label(): string
    {
        return 'Cross-Origin-Opener-Policy';
    }
}
