<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures;

use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeContract;

enum ValidConsumerReportType: string implements ReportTypeContract
{
    case CspViolation = 'csp-violation';
    case DocumentPolicyViolation = 'document-policy-violation';

    public function label(): string
    {
        return match ($this) {
            self::CspViolation => 'CSP violation',
            self::DocumentPolicyViolation => 'Document policy violation',
        };
    }
}
