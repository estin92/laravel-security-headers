<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Support\TrustworthyLocalHost;

test('it accepts localhost and its subdomains', function (string $host) {
    expect(TrustworthyLocalHost::matches($host))->toBeTrue();
})->with([
    'localhost' => ['localhost'],
    'subdomain' => ['app.localhost'],
    'ipv6 loopback' => ['[::1]'],
    '127.0.0.1' => ['127.0.0.1'],
    '127.x block' => ['127.5.6.7'],
    'uppercase' => ['LOCALHOST'],
    'mixed-case subdomain' => ['App.LocalHost'],
]);

test('it accepts the bracketed IPv6 loopback that parse_url produces', function () {
    // parse_url keeps the brackets on an IPv6 host, so the bracketed form is what call sites pass.
    expect(parse_url('http://[::1]/x')['host'])->toBe('[::1]');
    expect(TrustworthyLocalHost::matches('[::1]'))->toBeTrue();
});

test('it rejects hosts that are not trustworthy loopback', function (string $host) {
    expect(TrustworthyLocalHost::matches($host))->toBeFalse();
})->with([
    'public host' => ['example.com'],
    'localhost as label prefix' => ['localhost.domain.com'],
    'contains localhost' => ['notlocalhost.domain.com'],
    'fake loopback suffix' => ['127.0.0.1.domain.com'],
    'impossible octet' => ['127.999.0.1'],
    '10.x private' => ['10.0.0.1'],
    'unbracketed ipv6 loopback' => ['::1'],
    'global ipv6 address' => ['[2001:db8::1]'],
    'empty' => [''],
]);
