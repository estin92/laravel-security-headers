<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Csp\CspCompiler;
use Estin92\SecurityHeaders\Csp\StrictPolicy;

test('it compiles to a strict baseline policy with a script nonce', function () {
    $compiled = (new CspCompiler)->compile(new StrictPolicy, 'testnonce');

    expect($compiled)->toBe(implode('; ', [
        "default-src 'self'",
        "script-src 'self' 'nonce-testnonce'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "object-src 'none'",
        'upgrade-insecure-requests',
    ]));
});

test('the strict policy requires a nonce', function () {
    expect((new StrictPolicy)->requiresNonce())->toBeTrue();
});
