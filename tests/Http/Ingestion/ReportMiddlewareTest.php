<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Http\Middleware\Ingestion\EnforceReportBodySize;
use Estin92\SecurityHeaders\Http\Middleware\Ingestion\HandleReportCors;
use Estin92\SecurityHeaders\Http\Middleware\Ingestion\ThrottleReportSubmissions;
use Estin92\SecurityHeaders\Reporting\Ingestion\DefaultIngestionRateLimiter;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportSubmissionRejected;
use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;

beforeEach(function () {
    config()->set('cache.default', 'array');
    RateLimiter::for('security-headers-ingestion', fn ($request) => (new DefaultIngestionRateLimiter)($request));

    Route::match(['POST', 'OPTIONS'], '/security/reports', fn () => response('', 204))
        ->middleware([HandleReportCors::class, EnforceReportBodySize::class, ThrottleReportSubmissions::class]);
});

function post(string $body = '[]', array $headers = []): TestResponse
{
    return test()->call('POST', '/security/reports', [], [], [], transformHeaders($headers), $body);
}

function transformHeaders(array $headers): array
{
    $server = ['CONTENT_TYPE' => $headers['Content-Type'] ?? 'application/reports+json'];

    if (isset($headers['Origin'])) {
        $server['HTTP_ORIGIN'] = $headers['Origin'];
    }

    return $server;
}

test('a preflight from an allowed origin gets CORS headers', function () {
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', ['https://app.example.com']);

    $response = test()->call('OPTIONS', '/security/reports', [], [], [], ['HTTP_ORIGIN' => 'https://app.example.com']);

    $response->assertNoContent(204);
    expect($response->headers->get('Access-Control-Allow-Origin'))->toBe('https://app.example.com');
    expect($response->headers->get('Access-Control-Allow-Methods'))->toBe('POST');
    expect($response->headers->get('Vary'))->toBe('Origin');
});

test('CORS decoration appends to an existing Vary header rather than replacing it', function () {
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', ['https://app.example.com']);

    $request = Request::create('/security/reports', 'POST');
    $request->headers->set('Origin', 'https://app.example.com');

    $middleware = new HandleReportCors(app(Dispatcher::class));
    $response = $middleware->handle($request, function () {
        $downstream = response('', 204);
        $downstream->headers->set('Vary', 'Accept-Encoding');

        return $downstream;
    });

    expect($response->headers->all('Vary'))->toContain('Accept-Encoding', 'Origin');
});

test('a preflight from a disallowed origin gets no CORS grant', function () {
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', ['https://app.example.com']);

    $response = test()->call('OPTIONS', '/security/reports', [], [], [], ['HTTP_ORIGIN' => 'https://evil.example.com']);

    $response->assertNoContent(204);
    expect($response->headers->has('Access-Control-Allow-Origin'))->toBeFalse();
});

test('an actual cross-origin POST from an allowed origin carries the ACAO header', function () {
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', ['https://app.example.com']);

    $response = post('[]', ['Origin' => 'https://app.example.com']);

    $response->assertNoContent(204);
    expect($response->headers->get('Access-Control-Allow-Origin'))->toBe('https://app.example.com');
});

test('an actual cross-origin POST from a disallowed origin is 403 with no ACAO', function () {
    Event::fake([ReportSubmissionRejected::class]);
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', ['https://app.example.com']);

    $response = post('[]', ['Origin' => 'https://evil.example.com']);

    $response->assertStatus(403);
    $response->assertJson(['error' => 'origin_not_allowed']);
    expect($response->headers->has('Access-Control-Allow-Origin'))->toBeFalse();
    Event::assertDispatched(ReportSubmissionRejected::class, fn ($e) => $e->reason === RejectionReason::OriginNotAllowed);
});

test('a POST with no Origin passes through', function () {
    $response = post('[]', ['Content-Type' => 'application/csp-report']);

    $response->assertNoContent(204);
});

test('a same-origin POST passes through even with an empty allow-list', function () {
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', []);

    $response = post('[]', ['Origin' => 'http://localhost']);

    $response->assertNoContent(204);
    expect($response->headers->has('Access-Control-Allow-Origin'))->toBeFalse();
});

test('a same-origin preflight returns 204 without CORS headers', function () {
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', []);

    $response = test()->call('OPTIONS', '/security/reports', [], [], [], ['HTTP_ORIGIN' => 'http://localhost']);

    $response->assertNoContent(204);
    expect($response->headers->has('Access-Control-Allow-Origin'))->toBeFalse();
});

test('an origin that is not a clean scheme-host is treated as disallowed', function (string $origin) {
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', ['https://app.example.com']);

    $response = post('[]', ['Origin' => $origin]);

    $response->assertStatus(403);
})->with([
    'literal null' => ['null'],
    'carries a path' => ['https://app.example.com/x'],
    'plain http non-local' => ['http://app.example.com'],
    'not a url' => ['@@@'],
]);

test('a disallowed-origin config entry never grants access', function () {
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', [123, 'https://app.example.com']);

    $response = post('[]', ['Origin' => 'https://other.example.com']);

    $response->assertStatus(403);
});

test('an unregistered named limiter fails closed with 503 and never reaches the route', function () {
    Event::fake([ReportSubmissionRejected::class]);
    config()->set('security-headers.reporting.ingestion.rate_limiting.limiter', 'never-registered');

    $response = post('[]');

    $response->assertStatus(503);
    $response->assertJson(['error' => 'service_unavailable']);
    Event::assertNotDispatched(ReportSubmissionRejected::class);
});

test('an unregistered limiter still gets CORS decoration for an allowed origin', function () {
    config()->set('security-headers.reporting.ingestion.rate_limiting.limiter', 'never-registered');
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', ['https://app.example.com']);

    $response = post('[]', ['Origin' => 'https://app.example.com']);

    $response->assertStatus(503);
    expect($response->headers->get('Access-Control-Allow-Origin'))->toBe('https://app.example.com');
});

test('a body over the size limit is 413 before it reaches the route', function () {
    Event::fake([ReportSubmissionRejected::class]);
    config()->set('security-headers.reporting.ingestion.limits.max_bytes', 10);

    $response = post(str_repeat('a', 50));

    $response->assertStatus(413);
    $response->assertJson(['error' => 'request_too_large']);
    Event::assertDispatched(ReportSubmissionRejected::class, fn ($e) => $e->reason === RejectionReason::RequestTooLarge);
});

test('exceeding the rate limit is 429 with Retry-After and the JSON body', function () {
    Event::fake([ReportSubmissionRejected::class]);
    config()->set('security-headers.reporting.ingestion.rate_limiting.reporting_api_per_minute', 1);

    post('[]');
    $response = post('[]');

    $response->assertStatus(429);
    $response->assertJson(['error' => 'rate_limited']);
    expect($response->headers->has('Retry-After'))->toBeTrue();
    Event::assertDispatched(ReportSubmissionRejected::class, fn ($e) => $e->reason === RejectionReason::RateLimited);
});

test('a consumer-selected named limiter is used instead of the default', function () {
    RateLimiter::for('my-limiter', fn () => Limit::perMinute(1)->by('fixed-key'));
    config()->set('security-headers.reporting.ingestion.rate_limiting.limiter', 'my-limiter');

    post('[]');
    $response = post('[]');

    $response->assertStatus(429);
});

test('the package per-minute settings do not override a custom limiter', function () {
    RateLimiter::for('my-limiter', fn () => Limit::perMinute(5)->by('fixed-key'));
    config()->set('security-headers.reporting.ingestion.rate_limiting.limiter', 'my-limiter');
    config()->set('security-headers.reporting.ingestion.rate_limiting.reporting_api_per_minute', 1);

    post('[]');
    $response = post('[]');

    $response->assertNoContent(204);
});

test('a throttled legacy request reports the legacy protocol on its event', function () {
    Event::fake([ReportSubmissionRejected::class]);
    config()->set('security-headers.reporting.ingestion.rate_limiting.legacy_csp_per_minute', 1);

    post('{"csp-report":{}}', ['Content-Type' => 'application/csp-report']);
    post('{"csp-report":{}}', ['Content-Type' => 'application/csp-report']);

    Event::assertDispatched(
        ReportSubmissionRejected::class,
        fn ($e) => $e->protocol === ReportProtocol::LegacyCspReportUri,
    );
});

test('the two protocols throttle in separate buckets', function () {
    config()->set('security-headers.reporting.ingestion.rate_limiting.reporting_api_per_minute', 1);
    config()->set('security-headers.reporting.ingestion.rate_limiting.legacy_csp_per_minute', 1);

    post('[]', ['Content-Type' => 'application/reports+json']);
    $legacy = post('{"csp-report":{}}', ['Content-Type' => 'application/csp-report']);

    $legacy->assertNoContent(204);
});

test('disabling the limiter turns throttling off', function () {
    config()->set('security-headers.reporting.ingestion.rate_limiting.enabled', false);
    config()->set('security-headers.reporting.ingestion.rate_limiting.reporting_api_per_minute', 1);

    post('[]');
    $response = post('[]');

    $response->assertNoContent(204);
});

test('an error response still carries CORS headers for an allowed origin', function () {
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', ['https://app.example.com']);
    config()->set('security-headers.reporting.ingestion.limits.max_bytes', 10);

    $response = post(str_repeat('a', 50), ['Origin' => 'https://app.example.com']);

    $response->assertStatus(413);
    expect($response->headers->get('Access-Control-Allow-Origin'))->toBe('https://app.example.com');
});
