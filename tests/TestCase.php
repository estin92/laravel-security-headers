<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests;

use Estin92\SecurityHeaders\SecurityHeadersServiceProvider;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    /**
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            SecurityHeadersServiceProvider::class,
        ];
    }
}
