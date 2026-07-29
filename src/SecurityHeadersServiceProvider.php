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

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/security-headers.php' => config_path('security-headers.php'),
        ], 'security-headers-config');

        $this->app->afterResolving(Kernel::class, function (Kernel $kernel) {
            if (config('security-headers.auto_register') === true) {
                $kernel->pushMiddleware(ApplySecurityHeaders::class);
            }
        });
    }
}
