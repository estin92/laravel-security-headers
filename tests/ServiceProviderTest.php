<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\SecurityHeadersServiceProvider;

test('the service provider is registered', function () {
    expect($this->app->getProviders(SecurityHeadersServiceProvider::class))
        ->not->toBeEmpty();
});
