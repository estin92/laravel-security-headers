<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Headers\SimpleHeaders;

test('it compiles enabled headers to a name and value map', function () {
    $headers = new SimpleHeaders([
        'x_frame_options' => ['enabled' => true, 'value' => 'DENY'],
        'referrer_policy' => ['enabled' => true, 'value' => 'no-referrer'],
    ]);

    expect($headers->compile())->toBe([
        'X-Frame-Options' => 'DENY',
        'Referrer-Policy' => 'no-referrer',
    ]);
});

test('it omits disabled headers', function () {
    $headers = new SimpleHeaders([
        'x_frame_options' => ['enabled' => true, 'value' => 'DENY'],
        'x_xss_protection' => ['enabled' => false, 'value' => '0'],
    ]);

    expect($headers->compile())->toBe([
        'X-Frame-Options' => 'DENY',
    ]);
});

test('it ignores keys that are not known headers', function () {
    $headers = new SimpleHeaders([
        'made_up_header' => ['enabled' => true, 'value' => 'anything'],
    ]);

    expect($headers->compile())->toBe([]);
});

test('it skips a header whose config is not the expected shape', function (mixed $entry) {
    $headers = new SimpleHeaders(['x_frame_options' => $entry]);

    expect($headers->compile())->toBe([]);
})->with([
    'plain string instead of array' => 'DENY',
    'missing enabled key' => [['value' => 'DENY']],
    'enabled is truthy but not true' => [['enabled' => 1, 'value' => 'DENY']],
    'enabled is the string "true"' => [['enabled' => 'true', 'value' => 'DENY']],
    'value is missing' => [['enabled' => true]],
    'value is not a string' => [['enabled' => true, 'value' => 123]],
]);
