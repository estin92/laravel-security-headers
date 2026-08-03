<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Support\Origin;

test('it normalises a plain https origin', function () {
    expect(Origin::normalize('https://app.example.com'))->toBe('https://app.example.com');
});

test('it keeps a non-default port', function () {
    expect(Origin::normalize('https://app.example.com:8443'))->toBe('https://app.example.com:8443');
});

test('it collapses the default port so it matches the origin a browser sends', function (string $origin, string $expected) {
    expect(Origin::normalize($origin))->toBe($expected);
})->with([
    'https 443' => ['https://app.example.com:443', 'https://app.example.com'],
    'http 80 on localhost' => ['http://localhost:80', 'http://localhost'],
]);

test('it normalises an IPv6 origin keeping the brackets', function (string $origin, ?string $expected) {
    expect(Origin::normalize($origin))->toBe($expected);
})->with([
    'https loopback' => ['https://[::1]', 'https://[::1]'],
    'http loopback is a trustworthy local host' => ['http://[::1]', 'http://[::1]'],
    'https loopback default port collapses' => ['https://[::1]:443', 'https://[::1]'],
    'https loopback non-default port kept' => ['https://[::1]:8443', 'https://[::1]:8443'],
    'https global address' => ['https://[2001:db8::1]', 'https://[2001:db8::1]'],
    'http global address rejected as not local' => ['http://[2001:db8::1]', null],
]);

test('it lowercases the scheme and host', function () {
    expect(Origin::normalize('HTTPS://App.Example.COM'))->toBe('https://app.example.com');
});

test('it allows http only for a trustworthy local host', function (string $origin, ?string $expected) {
    expect(Origin::normalize($origin))->toBe($expected);
})->with([
    'localhost' => ['http://localhost', 'http://localhost'],
    'localhost with port' => ['http://localhost:3000', 'http://localhost:3000'],
    'loopback' => ['http://127.0.0.1', 'http://127.0.0.1'],
    'public http rejected' => ['http://example.com', null],
]);

test('it rejects an origin that is not a bare scheme, host and port', function (string $origin) {
    expect(Origin::normalize($origin))->toBeNull();
})->with([
    'has a path' => ['https://app.example.com/reports'],
    'has a query' => ['https://app.example.com?a=1'],
    'has a fragment' => ['https://app.example.com#x'],
    'has credentials' => ['https://user:pass@app.example.com'],
]);

test('it rejects a value that is not an origin', function (string $origin) {
    expect(Origin::normalize($origin))->toBeNull();
})->with([
    'the literal null' => ['null'],
    'empty' => [''],
    'no scheme' => ['app.example.com'],
    'garbage' => ['@@@'],
]);
