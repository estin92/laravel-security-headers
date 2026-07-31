<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidReportingEndpoint;
use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;

test('it builds a valid https endpoint', function () {
    $endpoint = ReportingEndpoint::fromConfig('csp-enforce', ['url' => 'https://collector.example.com/csp']);

    expect($endpoint->name)->toBe('csp-enforce');
    expect($endpoint->url)->toBe('https://collector.example.com/csp');
    expect($endpoint->legacyUrl)->toBeNull();
    expect($endpoint->reportUri())->toBe('https://collector.example.com/csp');
});

test('it uses legacy_url for the report-uri value when present', function () {
    $endpoint = ReportingEndpoint::fromConfig('e', [
        'url' => 'https://modern.example.com/r',
        'legacy_url' => 'https://legacy.example.com/r',
    ]);

    expect($endpoint->reportUri())->toBe('https://legacy.example.com/r');
});

test('a null legacy_url falls back to url', function () {
    $endpoint = ReportingEndpoint::fromConfig('e', [
        'url' => 'https://modern.example.com/r',
        'legacy_url' => null,
    ]);

    expect($endpoint->reportUri())->toBe('https://modern.example.com/r');
});

test('it permits http for potentially-trustworthy local origins', function (string $url) {
    $endpoint = ReportingEndpoint::fromConfig('local', ['url' => $url]);

    expect($endpoint->url)->toBe($url);
})->with([
    'localhost' => ['http://localhost/r'],
    'localhost with port' => ['http://localhost:9000/r'],
    'localhost subdomain' => ['http://app.localhost/r'],
    '127.0.0.1' => ['http://127.0.0.1/r'],
    '127.x loopback block' => ['http://127.5.6.7:8080/r'],
    'ipv6 loopback' => ['http://[::1]:9000/r'],
]);

test('it rejects a missing or empty url', function (mixed $definition) {
    expect(fn () => ReportingEndpoint::fromConfig('e', $definition))
        ->toThrow(InvalidReportingEndpoint::class);
})->with([
    'no url key' => [[]],
    'null url' => [['url' => null]],
    'empty url' => [['url' => '']],
    'non-string url' => [['url' => 123]],
    'non-array definition' => ['not-an-array'],
]);

test('it rejects an invalid endpoint name', function (string $name) {
    expect(fn () => ReportingEndpoint::fromConfig($name, ['url' => 'https://a.example.com/r']))
        ->toThrow(InvalidReportingEndpoint::class);
})->with([
    'space' => ['csp enforce'],
    'uppercase' => ['CSP'],
    'leading digit' => ['1csp'],
    'quote' => ['csp"'],
    'empty' => [''],
]);

test('it rejects a non-http(s) scheme', function (string $url) {
    expect(fn () => ReportingEndpoint::fromConfig('e', ['url' => $url]))
        ->toThrow(InvalidReportingEndpoint::class);
})->with([
    'ftp' => ['ftp://a.example.com/r'],
    'javascript' => ['javascript:alert(1)'],
    'data' => ['data:text/plain,x'],
    'no scheme' => ['//a.example.com/r'],
]);

test('it rejects a malformed absolute url that parse_url would not', function (string $url) {
    expect(fn () => ReportingEndpoint::fromConfig('e', ['url' => $url]))
        ->toThrow(InvalidReportingEndpoint::class);
})->with([
    'empty authority' => ['https://'],
    'empty host' => ['http:///path'],
    'underscore in host' => ['https://exa_mple.com/r'],
    'leading-dash label' => ['https://-bad.example.com/r'],
    'trailing bare percent' => ['https://a.example.com/r%'],
    'percent one hex digit' => ['https://a.example.com/r%2'],
    'percent non-hex' => ['https://a.example.com/r%2Gx'],
]);

test('it rejects insecure http for a non-local host', function () {
    expect(fn () => ReportingEndpoint::fromConfig('e', ['url' => 'http://collector.example.com/r']))
        ->toThrow(InvalidReportingEndpoint::class);
});

test('it rejects a host that merely contains localhost', function (string $url) {
    expect(fn () => ReportingEndpoint::fromConfig('e', ['url' => $url]))
        ->toThrow(InvalidReportingEndpoint::class);
})->with([
    'localhost as label prefix' => ['http://localhost.domain.com/r'],
    'localhost in the middle' => ['http://notlocalhost.domain.com/r'],
    'fake loopback' => ['http://127.0.0.1.domain.com/r'],
    'impossible octet' => ['http://127.999.0.1/r'],
    'non-loopback ipv4' => ['http://10.0.0.1/r'],
    'loopback label prefix' => ['http://127.0.0.1.example.com/r'],
]);

test('it rejects url credentials', function () {
    expect(fn () => ReportingEndpoint::fromConfig('e', ['url' => 'https://user:pass@a.example.com/r']))
        ->toThrow(InvalidReportingEndpoint::class);
});

test('it rejects a url fragment', function () {
    expect(fn () => ReportingEndpoint::fromConfig('e', ['url' => 'https://a.example.com/r#frag']))
        ->toThrow(InvalidReportingEndpoint::class);
});

test('it rejects characters that could break out of the report-uri directive', function (string $url) {
    expect(fn () => ReportingEndpoint::fromConfig('e', ['url' => $url]))
        ->toThrow(InvalidReportingEndpoint::class);
})->with([
    'newline' => ["https://a.example.com/r\n"],
    'carriage return' => ["https://a.example.com/r\r"],
    'header split' => ["https://a.example.com/r\r\nSet-Cookie: x=1"],
    'null byte' => ["https://a.example.com/r\0"],
    'high byte' => ["https://a.example.com/r\xff"],
    'double quote' => ['https://a.example.com/r"'],
    'backslash' => ['https://a.example.com/r\\x'],
    'space' => ['https://a.example.com/a b'],
    'angle bracket' => ['https://a.example.com/<script>'],
    'semicolon ends the directive' => ['https://a.example.com/r; report-uri https://attacker.example.com'],
    'comma separates report-uri urls' => ['https://a.example.com/r,https://attacker.example.com'],
]);
