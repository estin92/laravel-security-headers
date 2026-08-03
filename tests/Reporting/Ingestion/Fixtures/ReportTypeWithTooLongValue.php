<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures;

use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeContract;

enum ReportTypeWithTooLongValue: string implements ReportTypeContract
{
    // 65 bytes: valid grammar, one over the 64-byte ceiling.
    case CspViolation = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function label(): string
    {
        return 'CSP violation';
    }
}
