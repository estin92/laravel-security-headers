<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests\Http;

use Estin92\SecurityHeaders\Tests\TestCase;
use Illuminate\Foundation\Application;

abstract class WithIngestionEnabled extends TestCase
{
    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('security-headers.auto_register', false);
        $app['config']->set('security-headers.reporting.ingestion.enabled', true);
        $app['config']->set('cache.default', 'array');
    }
}
