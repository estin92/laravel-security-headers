<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidPermissionsPolicy;
use Estin92\SecurityHeaders\PermissionsPolicy\Keyword;
use Estin92\SecurityHeaders\PermissionsPolicy\PermissionsPolicyCompiler;

test('it returns null when there are no features', function () {
    expect((new PermissionsPolicyCompiler)->compile([]))->toBeNull();
});

test('it denies a feature with an empty allowlist', function () {
    expect((new PermissionsPolicyCompiler)->compile(['camera' => []]))
        ->toBe('camera=()');
});

test('it allows a feature for self', function () {
    expect((new PermissionsPolicyCompiler)->compile(['fullscreen' => [Keyword::Self]]))
        ->toBe('fullscreen=(self)');
});

test('it allows a feature for any origin', function () {
    expect((new PermissionsPolicyCompiler)->compile(['autoplay' => [Keyword::Any]]))
        ->toBe('autoplay=*');
});

test('it quotes origin strings and leaves keywords unquoted', function () {
    $compiled = (new PermissionsPolicyCompiler)->compile([
        'geolocation' => [Keyword::Self, 'https://maps.example.com'],
    ]);

    expect($compiled)->toBe('geolocation=(self "https://maps.example.com")');
});

test('it joins multiple features with a comma and space', function () {
    $compiled = (new PermissionsPolicyCompiler)->compile([
        'camera' => [],
        'microphone' => [],
        'fullscreen' => [Keyword::Self],
    ]);

    expect($compiled)->toBe('camera=(), microphone=(), fullscreen=(self)');
});

test('it rejects a feature name that is not a valid token', function (string $feature) {
    expect(fn () => (new PermissionsPolicyCompiler)->compile([$feature => []]))
        ->toThrow(InvalidPermissionsPolicy::class);
})->with([
    'space' => ['ca mera'],
    'semicolon' => ['camera;'],
    'newline' => ["camera\n"],
    'uppercase' => ['Camera'],
]);

test('it rejects the wildcard combined with an origin', function () {
    expect(fn () => (new PermissionsPolicyCompiler)->compile([
        'geolocation' => [Keyword::Any, 'https://example.com'],
    ]))->toThrow(InvalidPermissionsPolicy::class);
});

test('it rejects the wildcard combined with self', function () {
    expect(fn () => (new PermissionsPolicyCompiler)->compile([
        'geolocation' => [Keyword::Self, Keyword::Any],
    ]))->toThrow(InvalidPermissionsPolicy::class);
});

test('it allows self combined with one or more origins', function () {
    $compiled = (new PermissionsPolicyCompiler)->compile([
        'geolocation' => [Keyword::Self, 'https://a.example.com', 'https://b.example.com'],
    ]);

    expect($compiled)->toBe('geolocation=(self "https://a.example.com" "https://b.example.com")');
});

test('it rejects a keyword passed as a raw string instead of the enum', function (string $keyword) {
    expect(fn () => (new PermissionsPolicyCompiler)->compile(['geolocation' => [$keyword]]))
        ->toThrow(InvalidPermissionsPolicy::class);
})->with([
    'self as string' => ['self'],
    'wildcard as string' => ['*'],
]);

test('it treats a non-array allowlist as deny-all', function () {
    expect((new PermissionsPolicyCompiler)->compile(['camera' => 'oops']))
        ->toBe('camera=()');
});

test('it rejects a non-string non-keyword allowlist item', function () {
    expect(fn () => (new PermissionsPolicyCompiler)->compile(['camera' => [123]]))
        ->toThrow(InvalidPermissionsPolicy::class);
});

test('it rejects a non-string feature name', function () {
    expect(fn () => (new PermissionsPolicyCompiler)->compile([0 => []]))
        ->toThrow(InvalidPermissionsPolicy::class);
});

test('it rejects an origin that would break out of the header', function (string $origin) {
    expect(fn () => (new PermissionsPolicyCompiler)->compile(['geolocation' => [$origin]]))
        ->toThrow(InvalidPermissionsPolicy::class);
})->with([
    'quote' => ['https://evil"'],
    'carriage return' => ["https://evil\r"],
    'newline' => ["https://evil\n"],
    'comma' => ['https://a.com, camera=self'],
    'space' => ['https://a b.com'],
    'empty' => [''],
]);
