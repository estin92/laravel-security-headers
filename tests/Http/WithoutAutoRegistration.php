<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests\Http;

use Estin92\SecurityHeaders\Tests\TestCase;
use Illuminate\Foundation\Application;

abstract class WithoutAutoRegistration extends TestCase
{
    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('security-headers.auto_register', false);
    }
}
