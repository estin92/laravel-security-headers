<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Middleware\Ingestion;

use Closure;
use Estin92\SecurityHeaders\Http\Ingestion\ErrorResponse;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportSubmissionRejected;
use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

final class EnforceReportBodySize
{
    public function __construct(private readonly Dispatcher $events) {}

    /**
     * @param  Closure(Request): SymfonyResponse  $next
     */
    public function handle(Request $request, Closure $next): SymfonyResponse
    {
        if (strlen($request->getContent()) > $this->maxBytes()) {
            $this->events->dispatch(new ReportSubmissionRejected(
                null,
                RejectionReason::RequestTooLarge,
                413,
                null,
                null,
            ));

            return ErrorResponse::for(RejectionReason::RequestTooLarge);
        }

        return $next($request);
    }

    private function maxBytes(): int
    {
        $max = config('security-headers.reporting.ingestion.limits.max_bytes');

        return is_numeric($max) ? (int) $max : 65536;
    }
}
