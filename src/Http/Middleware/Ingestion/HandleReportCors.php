<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Middleware\Ingestion;

use Closure;
use Estin92\SecurityHeaders\Http\Ingestion\ErrorResponse;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportSubmissionRejected;
use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use Estin92\SecurityHeaders\Support\Origin;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

final class HandleReportCors
{
    public function __construct(private readonly Dispatcher $events) {}

    /**
     * @param  Closure(Request): SymfonyResponse  $next
     */
    public function handle(Request $request, Closure $next): SymfonyResponse
    {
        $origin = $request->headers->get('Origin');

        // A same-origin request is the normal case and gets no CORS treatment
        // the allow-list only governs genuinely cross-origin requests.
        if ($origin === null || $this->isSameOrigin($request, $origin)) {
            return $request->isMethod('OPTIONS') ? new Response(status: 204) : $next($request);
        }

        $allowed = $this->isAllowed($origin);

        if ($request->isMethod('OPTIONS')) {
            return $this->preflight($allowed ? $origin : null);
        }

        if (! $allowed) {
            return $this->forbidden();
        }

        $response = $next($request);
        $this->decorate($response, $origin);

        return $response;
    }

    private function isSameOrigin(Request $request, string $origin): bool
    {
        $normalized = Origin::normalize($origin);

        return $normalized !== null && $normalized === Origin::normalize($request->getSchemeAndHttpHost());
    }

    private function preflight(?string $origin): SymfonyResponse
    {
        $response = new Response(status: 204);

        if ($origin !== null) {
            $this->decorate($response, $origin);
            $response->headers->set('Access-Control-Allow-Methods', 'POST');
            $response->headers->set('Access-Control-Allow-Headers', 'Content-Type');
        }

        return $response;
    }

    private function forbidden(): SymfonyResponse
    {
        $this->events->dispatch(new ReportSubmissionRejected(
            null,
            RejectionReason::OriginNotAllowed,
            403,
            null,
            null,
        ));

        return ErrorResponse::for(RejectionReason::OriginNotAllowed);
    }

    private function decorate(SymfonyResponse $response, string $origin): void
    {
        $response->headers->set('Access-Control-Allow-Origin', $origin);
        $response->headers->set('Vary', 'Origin');
    }

    private function isAllowed(string $origin): bool
    {
        $normalized = Origin::normalize($origin);

        if ($normalized === null) {
            return false;
        }

        foreach ($this->allowedOrigins() as $candidate) {
            if (is_string($candidate) && Origin::normalize($candidate) === $normalized) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<mixed>
     */
    private function allowedOrigins(): array
    {
        $origins = config('security-headers.reporting.ingestion.cors.allowed_origins');

        return is_array($origins) ? $origins : [];
    }
}
