<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests\Reporting\Ingestion;

use Estin92\SecurityHeaders\Tests\TestCase;
use Illuminate\Foundation\Application;

abstract class IngestionTestCase extends TestCase
{
    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('security-headers.reporting.ingestion.enabled', true);
        $app['config']->set('cache.default', 'array');
    }
}
