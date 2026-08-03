<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;

// Consumers wanting a different policy register their own named limiter instead.
final class DefaultIngestionRateLimiter
{
    public function __invoke(Request $request): Limit
    {
        $protocol = ReportProtocol::fromContentType((string) $request->headers->get('Content-Type', ''));

        $perMinute = $protocol === ReportProtocol::LegacyCspReportUri
            ? $this->configInt('legacy_csp_per_minute', 600)
            : $this->configInt('reporting_api_per_minute', 120);

        $bucket = $protocol instanceof ReportProtocol ? $protocol->value : 'unknown';

        return Limit::perMinute($perMinute)->by('security-reports:default:'.$bucket.':'.$request->ip());
    }

    private function configInt(string $key, int $default): int
    {
        // These per-minute keys are optional, so the default is a real fallback, not just an analyzer guard.
        $value = config('security-headers.reporting.ingestion.rate_limiting.'.$key);

        return is_int($value) ? $value : $default;
    }
}
