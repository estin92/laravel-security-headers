<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

enum ReportType: string implements ReportTypeContract
{
    case CspViolation = 'csp-violation';
    case Coep = 'coep';
    case Coop = 'coop';
    case NetworkError = 'network-error';

    public function label(): string
    {
        return match ($this) {
            self::CspViolation => 'CSP violation',
            self::Coep => 'Cross-Origin-Embedder-Policy',
            self::Coop => 'Cross-Origin-Opener-Policy',
            self::NetworkError => 'Network error',
        };
    }
}
