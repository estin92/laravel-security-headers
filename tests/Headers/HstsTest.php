<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Headers\Hsts;

test('it returns null when hsts is disabled', function () {
    $hsts = new Hsts(['enabled' => false]);

    expect($hsts->compile())->toBeNull();
});

test('it assembles max-age with subdomains by default', function () {
    $hsts = new Hsts([
        'enabled' => true,
        'max_age' => 31536000,
        'include_subdomains' => true,
        'preload' => false,
    ]);

    expect($hsts->compile())->toBe('max-age=31536000; includeSubDomains');
});

test('it omits the subdomains token when include_subdomains is false', function () {
    $hsts = new Hsts([
        'enabled' => true,
        'max_age' => 31536000,
        'include_subdomains' => false,
        'preload' => false,
    ]);

    expect($hsts->compile())->toBe('max-age=31536000');
});

test('it appends preload when enabled', function () {
    $hsts = new Hsts([
        'enabled' => true,
        'max_age' => 63072000,
        'include_subdomains' => true,
        'preload' => true,
    ]);

    expect($hsts->compile())->toBe('max-age=63072000; includeSubDomains; preload');
});

test('it emits only max-age when the flags are absent', function () {
    $hsts = new Hsts(['enabled' => true]);

    expect($hsts->compile())->toBe('max-age=31536000');
});

test('a hostile max-age cannot escape the header value', function (string $maxAge) {
    $hsts = new Hsts([
        'enabled' => true,
        'max_age' => $maxAge,
        'include_subdomains' => false,
        'preload' => false,
    ]);

    $value = $hsts->compile();

    expect($value)->toBe('max-age=31536000');
    expect($value)->not->toContain("\r");
    expect($value)->not->toContain("\n");
})->with([
    'crlf injection' => ["31536000\r\nSet-Cookie: x=1"],
    'newline injection' => ["31536000\nX-Injected: 1"],
    'trailing space' => ['31536000 '],
    'digits with delimiter' => ['31536000; preload'],
]);

test('it returns null when the config is not the expected shape', function (mixed $config) {
    $hsts = new Hsts($config);

    expect($hsts->compile())->toBeNull();
})->with([
    'enabled missing' => [['max_age' => 31536000]],
    'enabled is truthy but not true' => [['enabled' => 1, 'max_age' => 31536000]],
    'enabled is the string "true"' => [['enabled' => 'true', 'max_age' => 31536000]],
]);

test('it accepts a numeric string max-age as env would supply it', function () {
    $hsts = new Hsts([
        'enabled' => true,
        'max_age' => '63072000',
        'include_subdomains' => false,
        'preload' => false,
    ]);

    expect($hsts->compile())->toBe('max-age=63072000');
});

test('it falls back to a safe max-age when the configured value is unusable', function (mixed $maxAge) {
    $hsts = new Hsts([
        'enabled' => true,
        'max_age' => $maxAge,
        'include_subdomains' => false,
        'preload' => false,
    ]);

    expect($hsts->compile())->toBe('max-age=31536000');
})->with([
    'missing' => [null],
    'non-numeric string' => ['forever'],
    'float' => [1.5],
    'zero' => [0],
    'negative' => [-1],
    'negative string' => ['-1'],
    'boolean true' => [true],
    'boolean false' => [false],
    'array' => [[31536000]],
]);
