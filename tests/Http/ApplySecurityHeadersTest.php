<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Csp\CspPolicy;
use Estin92\SecurityHeaders\Csp\StrictPolicy;
use Estin92\SecurityHeaders\Exceptions\InvalidCspPolicy;
use Estin92\SecurityHeaders\Http\Middleware\ApplySecurityHeaders;
use Estin92\SecurityHeaders\PermissionsPolicy\Allow;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Vite;

class NoncelessPolicy extends CspPolicy
{
    protected function define(): void
    {
        $this->directive('default-src', "'self'");
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
            'fullscreen' => [Allow::Self],
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

test('it applies the content-security-policy when csp is enabled', function () {
    config()->set('security-headers.csp', [
        'enabled' => true,
        'policy' => StrictPolicy::class,
    ]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $response = $this->get('/probe');

    $response->assertHeader('Content-Security-Policy');
    expect($response->headers->get('Content-Security-Policy'))->toContain("default-src 'self'");
});

test('it omits the content-security-policy when csp is disabled', function () {
    config()->set('security-headers.csp', ['enabled' => false, 'policy' => StrictPolicy::class]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $this->get('/probe')->assertHeaderMissing('Content-Security-Policy');
});

test('the header carries the nonce that Vite holds for the request', function () {
    config()->set('security-headers.csp', [
        'enabled' => true,
        'policy' => StrictPolicy::class,
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
        'enabled' => true,
        'policy' => StrictPolicy::class,
    ]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $first = $this->get('/probe')->headers->get('Content-Security-Policy');
    $second = $this->get('/probe')->headers->get('Content-Security-Policy');

    expect($first)->not->toBe($second);
});

test('it fails loudly when the configured policy is not a policy class', function () {
    config()->set('security-headers.csp', [
        'enabled' => true,
        'policy' => 'Not\\A\\Real\\Policy',
    ]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $this->withoutExceptionHandling();

    expect(fn () => $this->get('/probe'))->toThrow(InvalidCspPolicy::class);
});

test('it does not mint a nonce for a policy that does not need one', function () {
    config()->set('security-headers.csp', [
        'enabled' => true,
        'policy' => NoncelessPolicy::class,
    ]);

    Route::middleware(ApplySecurityHeaders::class)->get('/probe', fn () => 'ok');

    $response = $this->get('/probe');

    expect($response->headers->get('Content-Security-Policy'))->not->toContain('nonce-');
});
