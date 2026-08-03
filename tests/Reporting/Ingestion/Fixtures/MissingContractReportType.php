<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures;

enum MissingContractReportType: string
{
    case CspViolation = 'csp-violation';
}
