<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidHeaderValue;
use Estin92\SecurityHeaders\Headers\FlatHeaderCompiler;

test('it compiles enabled headers to a name and value map', function () {
    $headers = new FlatHeaderCompiler([
        'x_frame_options' => ['enabled' => true, 'value' => 'DENY'],
        'referrer_policy' => ['enabled' => true, 'value' => 'no-referrer'],
    ]);

    expect($headers->compile())->toBe([
        'X-Frame-Options' => 'DENY',
        'Referrer-Policy' => 'no-referrer',
    ]);
});

test('it compiles the cross-origin resource policy header', function () {
    $headers = new FlatHeaderCompiler([
        'cross_origin_resource_policy' => ['enabled' => true, 'value' => 'same-origin'],
    ]);

    expect($headers->compile())->toBe([
        'Cross-Origin-Resource-Policy' => 'same-origin',
    ]);
});

test('it rejects an invalid value for a header with a fixed value set', function (string $key, string $header, string $value) {
    $headers = new FlatHeaderCompiler([$key => ['enabled' => true, 'value' => $value]]);

    expect(fn () => $headers->compile())->toThrow(InvalidHeaderValue::class);
})->with([
    'corp typo' => ['cross_origin_resource_policy', 'Cross-Origin-Resource-Policy', 'same_origin'],
]);

test('it accepts every valid value for the cross-origin resource policy', function (string $key, string $value) {
    $headers = new FlatHeaderCompiler([$key => ['enabled' => true, 'value' => $value]]);

    expect($headers->compile())->toHaveCount(1);
})->with([
    ['cross_origin_resource_policy', 'same-site'],
    ['cross_origin_resource_policy', 'same-origin'],
    ['cross_origin_resource_policy', 'cross-origin'],
]);

test('it rejects a value carrying a header-injection payload', function (string $key, string $value) {
    $headers = new FlatHeaderCompiler([$key => ['enabled' => true, 'value' => $value]]);

    expect(fn () => $headers->compile())->toThrow(InvalidHeaderValue::class);
})->with([
    'corp bare cr' => ['cross_origin_resource_policy', "same-origin\r"],
    'unvalidated header crlf' => ['referrer_policy', "no-referrer\r\nInjected: value"],
]);

test('it accepts valid values for the older fixed-value headers', function (string $key, string $value) {
    $headers = new FlatHeaderCompiler([$key => ['enabled' => true, 'value' => $value]]);

    expect($headers->compile())->toHaveCount(1);
})->with([
    ['x_frame_options', 'DENY'],
    ['x_frame_options', 'SAMEORIGIN'],
    ['x_content_type_options', 'nosniff'],
    ['x_xss_protection', '0'],
    ['x_xss_protection', '1'],
    ['x_xss_protection', '1; mode=block'],
    ['referrer_policy', 'no-referrer'],
    ['referrer_policy', 'strict-origin-when-cross-origin'],
]);

test('it rejects invalid values for the older fixed-value headers', function (string $key, string $value) {
    $headers = new FlatHeaderCompiler([$key => ['enabled' => true, 'value' => $value]]);

    expect(fn () => $headers->compile())->toThrow(InvalidHeaderValue::class);
})->with([
    'x-frame lowercase' => ['x_frame_options', 'deny'],
    'x-frame typo' => ['x_frame_options', 'SAME-ORIGIN'],
    'content-type wrong' => ['x_content_type_options', 'sniff'],
    'xss report form' => ['x_xss_protection', '1; report=https://example.com'],
    'xss typo' => ['x_xss_protection', '2'],
    'referrer typo' => ['referrer_policy', 'no-refferer'],
]);

test('it accepts a referrer-policy fallback list', function () {
    $headers = new FlatHeaderCompiler([
        'referrer_policy' => ['enabled' => true, 'value' => 'no-referrer, strict-origin-when-cross-origin'],
    ]);

    expect($headers->compile())->toBe([
        'Referrer-Policy' => 'no-referrer, strict-origin-when-cross-origin',
    ]);
});

test('it rejects a referrer-policy list containing an invalid token', function () {
    $headers = new FlatHeaderCompiler([
        'referrer_policy' => ['enabled' => true, 'value' => 'no-referrer, not-a-policy'],
    ]);

    expect(fn () => $headers->compile())->toThrow(InvalidHeaderValue::class);
});

test('the shipped config enables corp as a flat header but not coop', function () {
    $config = require dirname(__DIR__, 2).'/config/security-headers.php';

    $compiled = (new FlatHeaderCompiler($config['headers']))->compile();

    expect($compiled)->toHaveKey('Cross-Origin-Resource-Policy');
    expect($compiled['Cross-Origin-Resource-Policy'])->toBe('same-origin');
    expect($compiled)->not->toHaveKey('Cross-Origin-Opener-Policy');
    expect($compiled)->not->toHaveKey('Cross-Origin-Embedder-Policy');
});

test('it omits disabled headers', function () {
    $headers = new FlatHeaderCompiler([
        'x_frame_options' => ['enabled' => true, 'value' => 'DENY'],
        'x_xss_protection' => ['enabled' => false, 'value' => '0'],
    ]);

    expect($headers->compile())->toBe([
        'X-Frame-Options' => 'DENY',
    ]);
});

test('it ignores keys that are not known headers', function () {
    $headers = new FlatHeaderCompiler([
        'made_up_header' => ['enabled' => true, 'value' => 'anything'],
    ]);

    expect($headers->compile())->toBe([]);
});

test('it skips a header whose config is not the expected shape', function (mixed $entry) {
    $headers = new FlatHeaderCompiler(['x_frame_options' => $entry]);

    expect($headers->compile())->toBe([]);
})->with([
    'plain string instead of array' => 'DENY',
    'missing enabled key' => [['value' => 'DENY']],
    'enabled is truthy but not true' => [['enabled' => 1, 'value' => 'DENY']],
    'enabled is the string "true"' => [['enabled' => 'true', 'value' => 'DENY']],
    'value is missing' => [['enabled' => true]],
    'value is not a string' => [['enabled' => true, 'value' => 123]],
]);
