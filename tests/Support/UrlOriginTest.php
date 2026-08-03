<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Support\UrlOrigin;

test('it returns scheme and host for a plain url', function () {
    expect(UrlOrigin::from('https://example.com/path?q=1'))->toBe('https://example.com');
});

test('it keeps a non-default port', function () {
    expect(UrlOrigin::from('https://example.com:8443/path'))->toBe('https://example.com:8443');
});

test('it drops the default port for the scheme', function (string $url, string $origin) {
    expect(UrlOrigin::from($url))->toBe($origin);
})->with([
    'https default' => ['https://example.com:443/x', 'https://example.com'],
    'http default' => ['http://example.com:80/x', 'http://example.com'],
]);

test('it lowercases the scheme and host', function () {
    expect(UrlOrigin::from('HTTPS://Example.COM/x'))->toBe('https://example.com');
});

test('it returns null for a url with no host', function (?string $url) {
    expect(UrlOrigin::from($url))->toBeNull();
})->with([
    'null' => [null],
    'empty' => [''],
    'data uri' => ['data:text/plain,hello'],
    'bare word' => ['inline'],
]);

test('it returns null when the derived origin exceeds 255 characters', function () {
    $host = str_repeat('a', 260).'.com';

    expect(UrlOrigin::from("https://{$host}/x"))->toBeNull();
});
