<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\SecurityHeadersServiceProvider;
use Illuminate\Support\Facades\Schema;

test('the service provider is registered', function () {
    expect($this->app->getProviders(SecurityHeadersServiceProvider::class))
        ->not->toBeEmpty();
});

test('the ingestion migration does not load when ingestion is disabled', function () {
    expect(config('security-headers.reporting.ingestion.enabled'))->toBeFalse();

    $this->artisan('migrate', ['--database' => 'testing']);

    expect(Schema::hasTable('security_reports'))->toBeFalse();
});
