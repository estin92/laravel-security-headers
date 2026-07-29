<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests;

use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\Attributes\WithConfig;
use PHPUnit\Framework\Attributes\Test;

class AutoRegisterDisabledTest extends TestCase
{
    #[Test]
    #[WithConfig('security-headers.auto_register', false)]
    public function it_does_not_register_the_middleware_when_auto_register_is_false(): void
    {
        Route::get('/plain', fn () => 'ok');

        $this->get('/plain')->assertHeaderMissing('X-Frame-Options');
    }
}
