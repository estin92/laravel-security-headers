<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders;

use Estin92\SecurityHeaders\Http\Middleware\ApplySecurityHeaders;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\ServiceProvider;

class SecurityHeadersServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/security-headers.php',
            'security-headers',
        );
    }

    public function boot(Kernel $kernel): void
    {
        $this->publishes([
            __DIR__.'/../config/security-headers.php' => config_path('security-headers.php'),
        ], 'security-headers-config');

        // Register on the kernel injected into boot. Do not use afterResolving():
        // under traditional/FPM bootstrapping the kernel may already be resolved before
        // this provider boots, so no later resolution occurs to fire the callback.
        if (config('security-headers.auto_register') === true) {
            $kernel->pushMiddleware(ApplySecurityHeaders::class);
        }
    }
}
