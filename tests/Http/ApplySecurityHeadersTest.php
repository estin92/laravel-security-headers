<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Csp\CspPolicy;
use Estin92\SecurityHeaders\Csp\Keyword as CspKeyword;
use Estin92\SecurityHeaders\Csp\StrictPolicy;
use Estin92\SecurityHeaders\Exceptions\InvalidCspPolicy;
use Estin92\SecurityHeaders\Exceptions\InvalidReportingEndpoint;
use Estin92\SecurityHeaders\Http\Middleware\ApplySecurityHeaders;
use Estin92\SecurityHeaders\PermissionsPolicy\Keyword;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Vite;

class NoncelessPolicy extends CspPolicy
{
    protected function define(): void
    {
        $this->directive('default-src', CspKeyword::Self);
    }
}

class SecondPolicy extends CspPolicy
{
    protected function define(): void
    {
        $this->directive('default-src', CspKeyword::None);
    }
}

class CountingPolicy extends CspPolicy
{
    public static int $defineCount = 0;

    protected function define(): void
    {
        self::$defineCount++;
        $this->directive('default-src', CspKeyword::Self);
    }
}

test('it applies the configured headers to the response', function () {
    config()->set('security-headers.headers', [
        'x_frame_options' => ['enabled' => true, 'value' => 'DENY'],
        'referrer_policy' => ['enabled' => false, 'value' => 'no-referrer'],
    ]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $response = $this->get('/probe');

    $response->assertHeader('X-Frame-Options', 'DENY');
    $response->assertHeaderMissing('Referrer-Policy');
});

test('it applies the permissions-policy when enabled', function () {
    config()->set('security-headers.permissions_policy', [
        'enabled' => true,
        'features' => [
            'camera' => [],
            'fullscreen' => [Keyword::Self],
        ],
    ]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $this->get('/probe')->assertHeader('Permissions-Policy', 'camera=(), fullscreen=(self)');
});

test('it omits the permissions-policy when disabled', function () {
    config()->set('security-headers.permissions_policy', ['enabled' => false, 'features' => ['camera' => []]]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $this->get('/probe')->assertHeaderMissing('Permissions-Policy');
});

test('it applies strict-transport-security when hsts is enabled', function () {
    config()->set('security-headers.hsts', [
        'enabled' => true,
        'max_age' => 31536000,
        'include_subdomains' => true,
        'preload' => false,
    ]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $this->get('/probe')->assertHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});

test('it omits strict-transport-security when hsts is disabled', function () {
    config()->set('security-headers.hsts', ['enabled' => false]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $this->get('/probe')->assertHeaderMissing('Strict-Transport-Security');
});

test('it emits the enforce header when the enforce channel is enabled', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $response = $this->get('/probe');
    $response->assertHeader('Content-Security-Policy');
    $response->assertHeaderMissing('Content-Security-Policy-Report-Only');
    expect($response->headers->get('Content-Security-Policy'))->toContain("default-src 'self'");
});

test('it emits the report-only header when the report-only channel is enabled', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => false, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => true, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $response = $this->get('/probe');
    $response->assertHeader('Content-Security-Policy-Report-Only');
    $response->assertHeaderMissing('Content-Security-Policy');
});

test('it emits both headers when both channels are enabled', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => true, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $response = $this->get('/probe');
    $response->assertHeader('Content-Security-Policy');
    $response->assertHeader('Content-Security-Policy-Report-Only');
});

test('it emits no CSP headers and mints no nonce when neither channel is enabled', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => false, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);

    $mintedNonce = 'unset';
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', function () use (&$mintedNonce) {
        $mintedNonce = Vite::cspNonce();

        return 'ok';
    });

    $response = $this->get('/probe');

    $response->assertHeaderMissing('Content-Security-Policy');
    $response->assertHeaderMissing('Content-Security-Policy-Report-Only');
    expect($mintedNonce)->toBeNull();
});

test('each channel emits its own configured policy', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => true, 'policy' => SecondPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $response = $this->get('/probe');

    $enforce = $response->headers->get('Content-Security-Policy');
    expect($enforce)->toBeString();
    expect($enforce)->toContain("script-src 'self'");
    expect($response->headers->get('Content-Security-Policy-Report-Only'))->toBe("default-src 'none'");
});

test('both channels share one nonce when both require one', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => true, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $response = $this->get('/probe');

    $enforce = $response->headers->get('Content-Security-Policy');
    $reportOnly = $response->headers->get('Content-Security-Policy-Report-Only');

    // Assert non-null first, then cast: the cast satisfies Larastan (?string →
    // string for preg_match); the assertion ensures a null hasn't been silently
    // cast to ''. Pest's toBeString() alone does not narrow the static type.
    expect($enforce)->toBeString();
    expect($reportOnly)->toBeString();

    expect(preg_match("/'nonce-([^']+)'/", (string) $enforce, $e))->toBe(1);
    expect(preg_match("/'nonce-([^']+)'/", (string) $reportOnly, $r))->toBe(1);
    expect($e[1])->toBe($r[1]);
});

test('a nonce is minted when only one channel requires it', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => NoncelessPolicy::class],
        'report_only' => ['enabled' => true, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $response = $this->get('/probe');
    expect($response->headers->get('Content-Security-Policy'))->not->toContain('nonce-');
    expect($response->headers->get('Content-Security-Policy-Report-Only'))->toContain('nonce-');
});

test('no nonce is minted when neither channel requires one', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => NoncelessPolicy::class],
        'report_only' => ['enabled' => false, 'policy' => NoncelessPolicy::class],
    ]);

    // Read the nonce inside the request: proves none was generated, not merely
    // absent from a nonce-free policy's header.
    $mintedNonce = 'unset';
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', function () use (&$mintedNonce) {
        $mintedNonce = Vite::cspNonce();

        return 'ok';
    });

    $this->get('/probe');

    expect($mintedNonce)->toBeNull();
});

test('it replaces pre-existing CSP headers on both channels rather than appending', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => true, 'policy' => SecondPolicy::class],
    ]);

    // Pre-seed both CSP headers so the test distinguishes set() (replaces) from
    // add() (would leave two) — a route with no prior header cannot.
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', function () {
        return response('ok')
            ->header('Content-Security-Policy', "default-src 'stale'")
            ->header('Content-Security-Policy-Report-Only', "default-src 'stale'");
    });

    $response = $this->get('/probe');

    $enforce = $response->headers->all('content-security-policy');
    expect($enforce)->toHaveCount(1);
    expect($enforce[0])->toContain("script-src 'self'");
    expect($enforce[0])->not->toContain('stale');

    $reportOnly = $response->headers->all('content-security-policy-report-only');
    expect($reportOnly)->toHaveCount(1);
    expect($reportOnly[0])->toBe("default-src 'none'");
    expect($reportOnly[0])->not->toContain('stale');
});

test('it fails loudly when an enabled channel has an invalid policy class', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => 'Not\\A\\Real\\Policy'],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $this->withoutExceptionHandling();
    expect(fn () => $this->get('/probe'))->toThrow(InvalidCspPolicy::class);
});

test('a disabled channel with an invalid policy class is ignored at runtime', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => false, 'policy' => 'Not\\A\\Real\\Policy'],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $this->get('/probe')->assertHeader('Content-Security-Policy');
});

test('an enabled channel resolves its policy exactly once', function () {
    CountingPolicy::$defineCount = 0;

    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => CountingPolicy::class],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $this->get('/probe');

    // One, despite the middleware calling requiresNonce() and directives()
    // separately — define() is memoised in CspPolicy.
    expect(CountingPolicy::$defineCount)->toBe(1);
});

test('the header carries the nonce that Vite holds for the request', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);

    $seen = null;

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', function () use (&$seen) {
        $seen = Vite::cspNonce();

        return 'ok';
    });

    $response = $this->get('/probe');

    expect($seen)->not->toBeNull();
    expect($response->headers->get('Content-Security-Policy'))->toContain("'nonce-{$seen}'");
});

test('two requests receive different nonces', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $first = $this->get('/probe')->headers->get('Content-Security-Policy');
    $second = $this->get('/probe')->headers->get('Content-Security-Policy');

    expect($first)->not->toBe($second);
});

test('it does not mint a nonce for a policy that does not need one', function () {
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => NoncelessPolicy::class],
        'report_only' => ['enabled' => false, 'policy' => NoncelessPolicy::class],
    ]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $response = $this->get('/probe');

    expect($response->headers->get('Content-Security-Policy'))->not->toContain('nonce-');
});

test('a channel with no reporting endpoint emits no reporting directives', function () {
    config()->set('security-headers.reporting.endpoints', [
        'csp' => ['url' => 'https://a.example.com/r'],
    ]);
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $response = $this->get('/probe');

    expect($response->headers->get('Content-Security-Policy'))->not->toContain('report-to');
    expect($response->headers->get('Content-Security-Policy'))->not->toContain('report-uri');
    $response->assertHeaderMissing('Reporting-Endpoints');
});

test('an enforce channel referencing an endpoint emits report-to, report-uri and the Reporting-Endpoints header', function () {
    config()->set('security-headers.reporting.endpoints', [
        'csp-enforce' => ['url' => 'https://a.example.com/e'],
    ]);
    config()->set('security-headers.csp', [
        'enforce' => [
            'enabled' => true,
            'policy' => StrictPolicy::class,
            'reporting_endpoint' => 'csp-enforce',
            'emit_legacy_report_uri' => true,
        ],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $response = $this->get('/probe');

    $csp = $response->headers->get('Content-Security-Policy');
    expect($csp)->toContain('report-to csp-enforce');
    expect($csp)->toContain('report-uri https://a.example.com/e');
    expect($response->headers->get('Reporting-Endpoints'))->toBe('csp-enforce="https://a.example.com/e"');
});

test('emit_legacy_report_uri false suppresses report-uri but keeps report-to', function () {
    config()->set('security-headers.reporting.endpoints', [
        'csp-enforce' => ['url' => 'https://a.example.com/e'],
    ]);
    config()->set('security-headers.csp', [
        'enforce' => [
            'enabled' => true,
            'policy' => StrictPolicy::class,
            'reporting_endpoint' => 'csp-enforce',
            'emit_legacy_report_uri' => false,
        ],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $csp = $this->get('/probe')->headers->get('Content-Security-Policy');

    expect($csp)->toContain('report-to csp-enforce');
    expect($csp)->not->toContain('report-uri');
});

test('legacy_url overrides the report-uri value', function () {
    config()->set('security-headers.reporting.endpoints', [
        'csp-enforce' => ['url' => 'https://a.example.com/e', 'legacy_url' => 'https://legacy.example.com/e'],
    ]);
    config()->set('security-headers.csp', [
        'enforce' => [
            'enabled' => true,
            'policy' => StrictPolicy::class,
            'reporting_endpoint' => 'csp-enforce',
            'emit_legacy_report_uri' => true,
        ],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $response = $this->get('/probe');

    expect($response->headers->get('Content-Security-Policy'))->toContain('report-uri https://legacy.example.com/e');
    expect($response->headers->get('Reporting-Endpoints'))->toContain('"https://a.example.com/e"');
});

test('two channels referencing the same endpoint produce one de-duplicated Reporting-Endpoints entry', function () {
    config()->set('security-headers.reporting.endpoints', [
        'shared' => ['url' => 'https://a.example.com/shared'],
    ]);
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class, 'reporting_endpoint' => 'shared'],
        'report_only' => ['enabled' => true, 'policy' => StrictPolicy::class, 'reporting_endpoint' => 'shared'],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $response = $this->get('/probe');

    expect($response->headers->get('Content-Security-Policy'))->toContain('report-to shared');
    expect($response->headers->get('Content-Security-Policy-Report-Only'))->toContain('report-to shared');
    expect($response->headers->get('Reporting-Endpoints'))->toBe('shared="https://a.example.com/shared"');
});

test('it replaces a pre-existing Reporting-Endpoints header rather than appending', function () {
    config()->set('security-headers.reporting.endpoints', [
        'csp-enforce' => ['url' => 'https://a.example.com/e'],
    ]);
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class, 'reporting_endpoint' => 'csp-enforce'],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', function () {
        return response('ok')->header('Reporting-Endpoints', 'stale="https://old.example.com/x"');
    });
    $response = $this->get('/probe');

    expect($response->headers->get('Reporting-Endpoints'))->toBe('csp-enforce="https://a.example.com/e"');
    expect($response->headers->all('reporting-endpoints'))->toHaveCount(1);
});

test('two channels referencing different endpoints produce two Reporting-Endpoints entries', function () {
    config()->set('security-headers.reporting.endpoints', [
        'e-enforce' => ['url' => 'https://a.example.com/e'],
        'e-candidate' => ['url' => 'https://b.example.com/c'],
    ]);
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class, 'reporting_endpoint' => 'e-enforce'],
        'report_only' => ['enabled' => true, 'policy' => StrictPolicy::class, 'reporting_endpoint' => 'e-candidate'],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $header = $this->get('/probe')->headers->get('Reporting-Endpoints');

    expect($header)->toContain('e-enforce="https://a.example.com/e"');
    expect($header)->toContain('e-candidate="https://b.example.com/c"');
});

test('no active channel references an endpoint means no Reporting-Endpoints header even when endpoints are declared', function () {
    config()->set('security-headers.reporting.endpoints', [
        'unused' => ['url' => 'https://a.example.com/r'],
    ]);
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $this->get('/probe')->assertHeaderMissing('Reporting-Endpoints');
});

test('an active channel with a dangling reference fails loudly', function () {
    config()->set('security-headers.reporting.endpoints', []);
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class, 'reporting_endpoint' => 'ghost'],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $this->withoutExceptionHandling();

    expect(fn () => $this->get('/probe'))->toThrow(InvalidReportingEndpoint::class);
});

test('a disabled channel with a dangling reference is ignored at runtime', function () {
    config()->set('security-headers.reporting.endpoints', []);
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class, 'reporting_endpoint' => 'ghost'],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $this->get('/probe')->assertHeader('Content-Security-Policy');
});

test('an active channel with a non-string reporting_endpoint fails loudly', function () {
    config()->set('security-headers.reporting.endpoints', []);
    config()->set('security-headers.csp', [
        'enforce' => ['enabled' => true, 'policy' => StrictPolicy::class, 'reporting_endpoint' => ['not', 'a', 'string']],
        'report_only' => ['enabled' => false, 'policy' => StrictPolicy::class],
    ]);
    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');
    $this->withoutExceptionHandling();

    expect(fn () => $this->get('/probe'))->toThrow(InvalidReportingEndpoint::class);
});
