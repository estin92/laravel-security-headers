<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

enum ReportProtocol: string
{
    case ReportingApi = 'reporting-api';
    case LegacyCspReportUri = 'legacy-csp-report-uri';

    public static function fromContentType(string $contentType): ?self
    {
        $type = strtolower(trim($contentType));
        $semicolon = strpos($type, ';');
        $media = $semicolon === false ? $type : trim(substr($type, 0, $semicolon));

        return match ($media) {
            'application/reports+json' => self::ReportingApi,
            'application/csp-report' => self::LegacyCspReportUri,
            default => null,
        };
    }
}
