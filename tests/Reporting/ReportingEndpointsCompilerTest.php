<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;
use Estin92\SecurityHeaders\Reporting\ReportingEndpointsCompiler;

function endpoint(string $name, string $url): ReportingEndpoint
{
    return ReportingEndpoint::fromConfig($name, ['url' => $url]);
}

test('it serialises one endpoint as a structured-fields dictionary member', function () {
    $out = (new ReportingEndpointsCompiler)->compile([
        'csp' => endpoint('csp', 'https://a.example.com/r'),
    ]);

    expect($out)->toBe('csp="https://a.example.com/r"');
});

test('it serialises multiple endpoints in insertion order, comma-separated', function () {
    $out = (new ReportingEndpointsCompiler)->compile([
        'enforce' => endpoint('enforce', 'https://a.example.com/e'),
        'candidate' => endpoint('candidate', 'https://b.example.com/c'),
    ]);

    expect($out)->toBe('enforce="https://a.example.com/e", candidate="https://b.example.com/c"');
});

test('a url with percent-encoded reserved bytes serialises verbatim', function () {
    $out = (new ReportingEndpointsCompiler)->compile([
        'e' => endpoint('e', 'https://a.example.com/a%22b%5Cc'),
    ]);

    expect($out)->toBe('e="https://a.example.com/a%22b%5Cc"');
});

test('an empty set compiles to an empty string', function () {
    expect((new ReportingEndpointsCompiler)->compile([]))->toBe('');
});
