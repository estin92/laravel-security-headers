<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Http\Middleware\ApplySecurityHeaders;
use Estin92\SecurityHeaders\SecurityHeadersServiceProvider;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\Facades\Route;

test('auto-registration applies headers to a plain route', function () {
    Route::get('/plain', fn () => 'ok');

    $this->get('/plain')->assertHeader('X-Frame-Options', 'DENY');
});

test('the provider pushes the middleware onto the kernel during boot', function () {
    config()->set('security-headers.auto_register', true);

    $kernel = Mockery::mock(Kernel::class);
    $kernel->shouldReceive('pushMiddleware')->once()->with(ApplySecurityHeaders::class);

    (new SecurityHeadersServiceProvider(app()))->boot($kernel);
});

test('the provider does not push the middleware when auto-registration is disabled', function () {
    config()->set('security-headers.auto_register', false);

    $kernel = Mockery::mock(Kernel::class);
    $kernel->shouldNotReceive('pushMiddleware');

    (new SecurityHeadersServiceProvider(app()))->boot($kernel);
});
