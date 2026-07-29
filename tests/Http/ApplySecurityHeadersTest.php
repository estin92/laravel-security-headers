<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Http\Middleware\ApplySecurityHeaders;
use Illuminate\Support\Facades\Route;

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
