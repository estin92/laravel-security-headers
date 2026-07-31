<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Tests\Http\WithoutAutoRegistration;
use Estin92\SecurityHeaders\Tests\TestCase;

// Http tests disable auto-registration so the route-attached middleware runs
// once, not twice. Bindings cannot overlap, so the base case is enumerated.
uses(WithoutAutoRegistration::class)->in(__DIR__.'/Http');
uses(TestCase::class)->in(
    __DIR__.'/Coep',
    __DIR__.'/Csp',
    __DIR__.'/Headers',
    __DIR__.'/PermissionsPolicy',
    __DIR__.'/Reporting',
    __DIR__.'/AutoRegistrationTest.php',
    __DIR__.'/ServiceProviderTest.php',
);
