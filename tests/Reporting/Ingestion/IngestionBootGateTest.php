<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidIngestionConfig;
use Estin92\SecurityHeaders\SecurityHeadersServiceProvider;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;

test('the provider refuses to boot ingestion with an invalid config', function () {
    config()->set('security-headers.reporting.ingestion.enabled', true);
    config()->set('security-headers.reporting.ingestion.limits.max_bytes', 999999999);

    $provider = new SecurityHeadersServiceProvider(app());

    expect(fn () => $provider->boot(app(Kernel::class)))
        ->toThrow(InvalidIngestionConfig::class);
});

test('the provider boots ingestion cleanly with the default config', function () {
    config()->set('security-headers.reporting.ingestion.enabled', true);

    $provider = new SecurityHeadersServiceProvider(app());

    expect(fn () => $provider->boot(app(Kernel::class)))
        ->not->toThrow(InvalidIngestionConfig::class);
});

test('the default limiter resolves so the boot check passes', function () {
    config()->set('security-headers.reporting.ingestion.enabled', true);
    (new SecurityHeadersServiceProvider(app()))->boot(app(Kernel::class));

    expect(fn () => SecurityHeadersServiceProvider::assertRateLimiterRegistered('security-headers-ingestion'))
        ->not->toThrow(InvalidIngestionConfig::class);
});

test('a registered consumer limiter passes the boot check', function () {
    RateLimiter::for('consumer-limiter', fn () => Limit::perMinute(10));

    expect(fn () => SecurityHeadersServiceProvider::assertRateLimiterRegistered('consumer-limiter'))
        ->not->toThrow(InvalidIngestionConfig::class);
});

test('an unregistered limiter name fails the boot check', function () {
    expect(fn () => SecurityHeadersServiceProvider::assertRateLimiterRegistered('never-registered'))
        ->toThrow(InvalidIngestionConfig::class);
});

test('booting with rate limiting disabled needs no named limiter', function () {
    config()->set('security-headers.reporting.ingestion.enabled', true);
    config()->set('security-headers.reporting.ingestion.rate_limiting.enabled', false);
    config()->set('security-headers.reporting.ingestion.rate_limiting.limiter', 'does-not-exist');

    $provider = new SecurityHeadersServiceProvider(app());

    expect(fn () => $provider->boot(app(Kernel::class)))
        ->not->toThrow(InvalidIngestionConfig::class);
});

test('the route binds to a configured domain', function () {
    config()->set('security-headers.reporting.ingestion.enabled', true);
    config()->set('security-headers.reporting.ingestion.route.domain', 'reports.example.com');

    (new SecurityHeadersServiceProvider(app()))->boot(app(Kernel::class));

    $route = collect(Route::getRoutes()->getRoutes())
        ->first(fn ($r) => $r->uri() === 'security/reports');

    expect($route?->getDomain())->toBe('reports.example.com');
});
