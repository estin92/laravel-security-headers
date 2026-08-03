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

test('it rejects hosts that are not trustworthy loopback', function (string $host) {
    expect(TrustworthyLocalHost::matches($host))->toBeFalse();
})->with([
    'public host' => ['example.com'],
    'localhost as label prefix' => ['localhost.domain.com'],
    'contains localhost' => ['notlocalhost.domain.com'],
    'fake loopback suffix' => ['127.0.0.1.domain.com'],
    'impossible octet' => ['127.999.0.1'],
    '10.x private' => ['10.0.0.1'],
    'empty' => [''],
]);
