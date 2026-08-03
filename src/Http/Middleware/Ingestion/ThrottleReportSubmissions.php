<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Middleware\Ingestion;

use Closure;
use Estin92\SecurityHeaders\Http\Ingestion\ErrorResponse;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportSubmissionRejected;
use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

final class ThrottleReportSubmissions
{
    public function __construct(
        private readonly RateLimiter $limiter,
        private readonly Dispatcher $events,
        private readonly LoggerInterface $logger,
    ) {}

    /**
     * @param  Closure(Request): SymfonyResponse  $next
     */
    public function handle(Request $request, Closure $next): SymfonyResponse
    {
        if (! $this->enabled()) {
            return $next($request);
        }

        $callback = $this->limiter->limiter($this->limiterName());

        if ($callback === null) {
            return $this->limiterUnavailable();
        }

        foreach ($this->toLimits($callback($request)) as $limit) {
            $key = $this->keyFor($limit);

            if ($this->limiter->tooManyAttempts($key, $limit->maxAttempts)) {
                return $this->rejected($request, $this->limiter->availableIn($key));
            }

            $this->limiter->hit($key, $limit->decaySeconds);
        }

        return $next($request);
    }

    /**
     * @return list<Limit>
     */
    private function toLimits(mixed $result): array
    {
        return array_values(array_filter(
            is_array($result) ? $result : [$result],
            fn (mixed $limit): bool => $limit instanceof Limit,
        ));
    }

    private function limiterUnavailable(): SymfonyResponse
    {
        // The submission was never evaluated, so this is a server-side config
        // failure (503), not a rejection or a rate-limit.
        $this->logger->error('The configured report ingestion rate limiter is not registered.', [
            'limiter' => $this->limiterName(),
        ]);

        return ErrorResponse::serviceUnavailable();
    }

    private function keyFor(Limit $limit): string
    {
        $key = is_scalar($limit->key) ? (string) $limit->key : '';

        return $this->limiterName().':'.md5($key);
    }

    private function rejected(Request $request, int $retryAfter): SymfonyResponse
    {
        $this->events->dispatch(new ReportSubmissionRejected(
            $this->protocol($request),
            RejectionReason::RateLimited,
            429,
            null,
            null,
        ));

        return ErrorResponse::for(RejectionReason::RateLimited, ['Retry-After' => (string) $retryAfter]);
    }

    private function protocol(Request $request): ?ReportProtocol
    {
        return ReportProtocol::fromContentType((string) $request->headers->get('Content-Type', ''));
    }

    private function enabled(): bool
    {
        return config('security-headers.reporting.ingestion.rate_limiting.enabled') !== false;
    }

    private function limiterName(): string
    {
        $name = config('security-headers.reporting.ingestion.rate_limiting.limiter');

        return is_string($name) ? $name : 'security-headers-ingestion';
    }
}
