<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests;

use Illuminate\Foundation\Application;

abstract class ViewerTestCase extends TestCase
{
    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('security-headers.reporting.ingestion.enabled', true);
        $app['config']->set('security-headers.reporting.viewer.enabled', true);
    }
}
