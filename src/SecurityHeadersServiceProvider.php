<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders;

use Estin92\SecurityHeaders\Console\AuditCommand;
use Estin92\SecurityHeaders\Console\PruneReportsCommand;
use Estin92\SecurityHeaders\Exceptions\InvalidIngestionConfig;
use Estin92\SecurityHeaders\Http\Controllers\ReportIngestionController;
use Estin92\SecurityHeaders\Http\Middleware\ApplySecurityHeaders;
use Estin92\SecurityHeaders\Http\Middleware\Ingestion\EnforceReportBodySize;
use Estin92\SecurityHeaders\Http\Middleware\Ingestion\EnsureStorageReady;
use Estin92\SecurityHeaders\Http\Middleware\Ingestion\HandleReportCors;
use Estin92\SecurityHeaders\Http\Middleware\Ingestion\ThrottleReportSubmissions;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\BodyValidatorRegistry;
use Estin92\SecurityHeaders\Reporting\Ingestion\DefaultIngestionRateLimiter;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionConfigValidator;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionPipeline;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionStorage;
use Estin92\SecurityHeaders\Reporting\Ingestion\LegacyCspReportDecoder;
use Estin92\SecurityHeaders\Reporting\Ingestion\ModernReportDecoder;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeResolver;
use Estin92\SecurityHeaders\Reporting\Ingestion\StoragePolicy;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\DatabaseManager;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;

class SecurityHeadersServiceProvider extends ServiceProvider
{
    public const VERSION = '0.1.0';

    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/security-headers.php',
            'security-headers',
        );

        $this->app->bind(IngestionPipeline::class, fn (Container $app): IngestionPipeline => $this->makePipeline($app));

        $this->app->singleton(EnsureStorageReady::class);
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

        // The ingestion table only exists for a consumer who opted in, so its
        // migration loads here rather than for every install.
        if (config('security-headers.reporting.ingestion.enabled') === true) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
            $this->bootIngestion();
        }
    }

    public static function assertRateLimiterRegistered(string $name): void
    {
        if (RateLimiter::limiter($name) === null) {
            throw InvalidIngestionConfig::unregisteredLimiter($name);
        }
    }

    /**
     * @throws BindingResolutionException
     */
    private function makePipeline(Container $app): IngestionPipeline
    {
        $ingestion = config('security-headers.reporting.ingestion');
        $ingestion = is_array($ingestion) ? $ingestion : [];

        $rawLimits = is_array($ingestion['limits'] ?? null) ? $ingestion['limits'] : [];
        $enum = is_string($ingestion['report_type_enum'] ?? null) ? $ingestion['report_type_enum'] : ReportType::class;
        $bodyValidators = is_array($ingestion['body_validators'] ?? null) ? $ingestion['body_validators'] : [];
        $storage = is_array($ingestion['storage'] ?? null) ? $ingestion['storage'] : [];

        $limits = [
            'max_bytes' => $this->limitValue($rawLimits, 'max_bytes', 65536),
            'max_reports_per_batch' => $this->limitValue($rawLimits, 'max_reports_per_batch', 100),
            'json_depth' => max(1, $this->limitValue($rawLimits, 'json_depth', 32)),
            'url_length' => $this->limitValue($rawLimits, 'url_length', 8192),
            'user_agent_length' => $this->limitValue($rawLimits, 'user_agent_length', 1024),
        ];

        $resolver = ReportTypeResolver::forEnum($enum);

        return new IngestionPipeline(
            new ModernReportDecoder($resolver, $limits),
            new LegacyCspReportDecoder($resolver, ['max_bytes' => $limits['max_bytes'], 'json_depth' => $limits['json_depth']]),
            new BodyValidatorRegistry($bodyValidators, $app),
            new StoragePolicy(['storage' => $storage]),
            $app->make(Dispatcher::class),
            $app->make(DatabaseManager::class)->connection(IngestionStorage::connection()),
            $app->make(LoggerInterface::class),
        );
    }

    /**
     * @param  array<mixed>  $limits
     */
    private function limitValue(array $limits, string $key, int $default): int
    {
        // Boot validation guarantees a present limit is a positive int; the default only covers absence.
        $value = $limits[$key] ?? $default;

        return is_int($value) ? $value : $default;
    }

    private function bootIngestion(): void
    {
        $config = config('security-headers.reporting.ingestion');
        (new IngestionConfigValidator)->validate(is_array($config) ? $config : []);

        $this->registerRateLimiter();
        $this->registerRoute();
        $this->verifyRateLimiterRegistered();

        if ($this->app->runningInConsole()) {
            $this->commands([AuditCommand::class, PruneReportsCommand::class]);
            $this->scheduleDailyPrune();
        }
    }

    private function verifyRateLimiterRegistered(): void
    {
        if (config('security-headers.reporting.ingestion.rate_limiting.enabled') === false) {
            return;
        }

        $name = config('security-headers.reporting.ingestion.rate_limiting.limiter');
        $name = is_string($name) ? $name : 'security-headers-ingestion';

        // Deferred so a consumer limiter registered in their own provider still counts.
        $this->app->booted(fn () => self::assertRateLimiterRegistered($name));
    }

    private function registerRateLimiter(): void
    {
        RateLimiter::for('security-headers-ingestion', fn (Request $request) => (new DefaultIngestionRateLimiter)($request));
    }

    private function registerRoute(): void
    {
        $path = config('security-headers.reporting.ingestion.route.path');
        $domain = config('security-headers.reporting.ingestion.route.domain');

        $route = Route::match(['POST', 'OPTIONS'], is_string($path) ? $path : '/security/reports', ReportIngestionController::class)
            ->middleware([HandleReportCors::class, EnsureStorageReady::class, EnforceReportBodySize::class, ThrottleReportSubmissions::class]);

        if (is_string($domain)) {
            $route->domain($domain);
        }
    }

    private function scheduleDailyPrune(): void
    {
        $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
            $schedule->command(PruneReportsCommand::class)->daily()->withoutOverlapping();
        });
    }
}
