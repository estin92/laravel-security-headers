<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidSanitizerConfig;
use Estin92\SecurityHeaders\Reporting\Ingestion\NormalizedReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportSubmission;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Reporting\Ingestion\Sanitizer;
use Estin92\SecurityHeaders\Reporting\Ingestion\SanitizerConfig;
use Estin92\SecurityHeaders\Reporting\Ingestion\StorageMode;
use Estin92\SecurityHeaders\Support\JsonObject;

function sanitizerConfig(array $overrides = []): SanitizerConfig
{
    return SanitizerConfig::fromArray(array_merge([
        'remove_client_ip' => true,
        'mask_client_ip' => false,
        'strip_query' => true,
        'remove_sample' => false,
        'remove_nel_headers' => true,
        'remove_request_user_agent' => false,
        'remove_reported_user_agent' => false,
    ], $overrides));
}

function body(array $fields): JsonObject
{
    return JsonObject::fromNative((object) $fields);
}

function submission(
    NormalizedReport $report,
    ?string $clientIp = '203.0.113.9',
    ?string $requestUa = 'req-UA',
): ReportSubmission {
    return new ReportSubmission($report, new DateTimeImmutable('2026-08-03T00:00:00Z'), $clientIp, $requestUa);
}

function cspReport(array $bodyFields, ?string $url = 'https://example.com/p?token=abc'): NormalizedReport
{
    return new NormalizedReport(
        ReportType::CspViolation,
        $url,
        10,
        'reported-UA',
        body($bodyFields),
        ReportProtocol::ReportingApi,
    );
}

function actionsFor(array $result): array
{
    return array_map(fn ($a) => [$a['path'], $a['action']], $result);
}

test('the default set removes the client IP, strips queries and removes NEL headers', function () {
    $report = cspReport([
        'blockedURL' => 'https://evil.example/x?session=1',
        'sample' => 'alert(1)',
    ]);

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->clientIp)->toBeNull();
    expect($result->url)->toBe('https://example.com/p');
    expect($result->body->get(['blockedURL']))->toBe('https://evil.example/x');
    expect($result->body->get(['sample']))->toBe('alert(1)');
});

test('strip_query strips the envelope url for every report type', function (ReportType $type) {
    $report = new NormalizedReport($type, 'https://example.com/p?q=1', 1, null, null, ReportProtocol::ReportingApi);

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->url)->toBe('https://example.com/p');
})->with([
    ReportType::CspViolation,
    ReportType::Coep,
    ReportType::Coop,
    ReportType::NetworkError,
]);

test('strip_query transforms every allow-listed CSP body field', function () {
    $report = cspReport([
        'documentURL' => 'https://example.com/a?x=1',
        'blockedURL' => 'https://evil.example/b?y=2',
        'sourceFile' => 'https://example.com/app.js?v=3',
        'referrer' => 'https://example.com/from?z=4',
    ]);

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->body->get(['documentURL']))->toBe('https://example.com/a');
    expect($result->body->get(['blockedURL']))->toBe('https://evil.example/b');
    expect($result->body->get(['sourceFile']))->toBe('https://example.com/app.js');
    expect($result->body->get(['referrer']))->toBe('https://example.com/from');
});

test('strip_query off leaves query strings on the url and body intact', function () {
    $report = cspReport(['blockedURL' => 'https://evil.example/b?y=2'], 'https://example.com/a?x=1');

    $result = (new Sanitizer(sanitizerConfig(['strip_query' => false]), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->url)->toBe('https://example.com/a?x=1');
    expect($result->body->get(['blockedURL']))->toBe('https://evil.example/b?y=2');
    expect(actionsFor($result->actions))->not->toContain([['url'], 'strip_query']);
    expect(actionsFor($result->actions))->not->toContain([['body', 'blockedURL'], 'strip_query']);
});

test('strip_query leaves an unknown CSP field carrying a URL untouched', function () {
    $report = cspReport(['customField' => 'https://example.com/keep?token=secret']);

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->body->get(['customField']))->toBe('https://example.com/keep?token=secret');
});

test('strip_query leaves a nested field named like an allow-listed one untouched', function () {
    $report = cspReport(['nested' => (object) ['blockedURL' => 'https://example.com/deep?token=secret']]);

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->body->get(['nested', 'blockedURL']))->toBe('https://example.com/deep?token=secret');
});

test('strip_query leaves URL-looking values in a COEP body untouched', function () {
    $report = new NormalizedReport(
        ReportType::Coep,
        'https://example.com/p?q=1',
        1,
        null,
        body(['blockedURL' => 'https://example.com/blocked?token=secret']),
        ReportProtocol::ReportingApi,
    );

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->body->get(['blockedURL']))->toBe('https://example.com/blocked?token=secret');
});

test('strip_query leaves CSP keywords like inline and eval untouched', function (string $blocked) {
    $report = cspReport(['blockedURL' => $blocked]);

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->body->get(['blockedURL']))->toBe($blocked);
})->with([
    'inline' => ['inline'],
    'eval' => ['eval'],
    'data' => ['data'],
    'empty' => [''],
]);

test('strip_query strips a url whose scheme is uppercase', function () {
    $report = cspReport(['blockedURL' => 'HTTPS://evil.example/x?session=1'], 'HTTP://example.com/p?token=abc');

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->url)->toBe('HTTP://example.com/p');
    expect($result->body->get(['blockedURL']))->toBe('HTTPS://evil.example/x');
});

test('an action is recorded only for an allow-listed value that actually changes', function () {
    $report = cspReport([
        'blockedURL' => 'https://evil.example/x?session=1',
        'sourceFile' => 'https://example.com/app.js',
    ]);

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect(actionsFor($result->actions))->toContain([['url'], 'strip_query']);
    expect(actionsFor($result->actions))->toContain([['body', 'blockedURL'], 'strip_query']);
    expect(actionsFor($result->actions))->not->toContain([['body', 'sourceFile'], 'strip_query']);
});

test('strip_query on a url with no query is not recorded', function () {
    $report = cspReport(['blockedURL' => 'https://evil.example/x'], 'https://example.com/p');

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect(actionsFor($result->actions))->not->toContain([['url'], 'strip_query']);
    expect(actionsFor($result->actions))->not->toContain([['body', 'blockedURL'], 'strip_query']);
});

test('the client IP removal is recorded', function () {
    $report = cspReport(['blockedURL' => 'https://evil.example/x']);

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect(actionsFor($result->actions))->toContain([['client_ip'], 'remove_client_ip']);
});

test('removing an absent client IP records nothing', function () {
    $report = cspReport(['blockedURL' => 'https://evil.example/x']);

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report, clientIp: null));

    expect(actionsFor($result->actions))->not->toContain([['client_ip'], 'remove_client_ip']);
    expect($result->clientIp)->toBeNull();
});

test('remove_nel_headers removes request and response headers', function () {
    $report = new NormalizedReport(
        ReportType::NetworkError,
        'https://example.com/p',
        1,
        null,
        body(['request_headers' => (object) ['x' => '1'], 'response_headers' => (object) ['y' => '2'], 'server_ip' => '10.0.0.1']),
        ReportProtocol::ReportingApi,
    );

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->body->has(['request_headers']))->toBeFalse();
    expect($result->body->has(['response_headers']))->toBeFalse();
    expect($result->body->get(['server_ip']))->toBe('10.0.0.1');
    expect(actionsFor($result->actions))->toContain([['body', 'request_headers'], 'remove_nel_headers']);
});

test('remove_nel_headers off leaves the headers in the body', function () {
    $report = new NormalizedReport(
        ReportType::NetworkError,
        'https://example.com/p',
        1,
        null,
        body(['request_headers' => (object) ['x' => '1'], 'response_headers' => (object) ['y' => '2']]),
        ReportProtocol::ReportingApi,
    );

    $result = (new Sanitizer(sanitizerConfig(['remove_nel_headers' => false]), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->body->has(['request_headers']))->toBeTrue();
    expect($result->body->has(['response_headers']))->toBeTrue();
    expect(actionsFor($result->actions))->not->toContain([['body', 'request_headers'], 'remove_nel_headers']);
});

test('remove_sample removes the CSP sample when enabled', function () {
    $report = cspReport(['sample' => 'alert(1)'], 'https://example.com/p');

    $result = (new Sanitizer(sanitizerConfig(['remove_sample' => true]), StorageMode::Sanitized))->sanitize(submission($report));

    expect($result->body->has(['sample']))->toBeFalse();
    expect(actionsFor($result->actions))->toContain([['body', 'sample'], 'remove_sample']);
});

test('the user agents are removed when their toggles are on', function () {
    $report = cspReport(['blockedURL' => 'https://evil.example/x'], 'https://example.com/p');

    $result = (new Sanitizer(
        sanitizerConfig(['remove_request_user_agent' => true, 'remove_reported_user_agent' => true]),
        StorageMode::Sanitized,
    ))->sanitize(submission($report));

    expect($result->requestUserAgent)->toBeNull();
    expect($result->reportedUserAgent)->toBeNull();
    expect(actionsFor($result->actions))->toContain([['request_user_agent'], 'remove_request_user_agent']);
    expect(actionsFor($result->actions))->toContain([['reported_user_agent'], 'remove_reported_user_agent']);
});

test('mask_client_ip masks a v4 address to its /24 network', function () {
    $report = cspReport(['blockedURL' => 'https://evil.example/x'], 'https://example.com/p');

    $result = (new Sanitizer(
        sanitizerConfig(['remove_client_ip' => false, 'mask_client_ip' => true]),
        StorageMode::Sanitized,
    ))->sanitize(submission($report, clientIp: '203.0.113.9'));

    expect($result->clientIp)->toBe('203.0.113.0');
    expect(actionsFor($result->actions))->toContain([['client_ip'], 'mask_client_ip']);
});

test('mask_client_ip masks a v6 address to its /48 network', function () {
    $report = cspReport(['blockedURL' => 'https://evil.example/x'], 'https://example.com/p');

    $result = (new Sanitizer(
        sanitizerConfig(['remove_client_ip' => false, 'mask_client_ip' => true]),
        StorageMode::Sanitized,
    ))->sanitize(submission($report, clientIp: '2001:db8:1234:5678::1'));

    expect($result->clientIp)->toBe('2001:db8:1234::');
});

test('an IP that cannot be masked is dropped, never kept exact', function () {
    $report = cspReport(['blockedURL' => 'https://evil.example/x'], 'https://example.com/p');

    $result = (new Sanitizer(
        sanitizerConfig(['remove_client_ip' => false, 'mask_client_ip' => true]),
        StorageMode::Sanitized,
    ))->sanitize(submission($report, clientIp: 'not-an-ip'));

    expect($result->clientIp)->toBeNull();
    expect(actionsFor($result->actions))->toContain([['client_ip'], 'remove_client_ip']);
});

test('an IP already on its network boundary masks to itself without recording', function () {
    $report = cspReport(['blockedURL' => 'https://evil.example/x'], 'https://example.com/p');

    $result = (new Sanitizer(
        sanitizerConfig(['remove_client_ip' => false, 'mask_client_ip' => true]),
        StorageMode::Sanitized,
    ))->sanitize(submission($report, clientIp: '203.0.113.0'));

    expect($result->clientIp)->toBe('203.0.113.0');
    expect(actionsFor($result->actions))->not->toContain([['client_ip'], 'mask_client_ip']);
});

test('raw mode keeps every value pristine and records no actions', function () {
    $report = cspReport(['blockedURL' => 'https://evil.example/x?session=1'], 'https://example.com/p?token=abc');

    $result = (new Sanitizer(sanitizerConfig(), StorageMode::Raw))->sanitize(submission($report, clientIp: '203.0.113.9'));

    expect($result->url)->toBe('https://example.com/p?token=abc');
    expect($result->clientIp)->toBe('203.0.113.9');
    expect($result->body->get(['blockedURL']))->toBe('https://evil.example/x?session=1');
    expect($result->actions)->toBe([]);
});

test('the input report body is not mutated by sanitizing', function () {
    $report = cspReport(['blockedURL' => 'https://evil.example/x?session=1'], 'https://example.com/p?token=abc');

    (new Sanitizer(sanitizerConfig(), StorageMode::Sanitized))->sanitize(submission($report));

    expect($report->body->get(['blockedURL']))->toBe('https://evil.example/x?session=1');
    expect($report->url)->toBe('https://example.com/p?token=abc');
});

test('remove and mask together is a config error', function () {
    expect(fn () => new Sanitizer(
        sanitizerConfig(['remove_client_ip' => true, 'mask_client_ip' => true]),
        StorageMode::Sanitized,
    ))->toThrow(InvalidSanitizerConfig::class);
});

test('neither removing nor masking the IP in sanitized mode is a config error', function () {
    expect(fn () => new Sanitizer(
        sanitizerConfig(['remove_client_ip' => false, 'mask_client_ip' => false]),
        StorageMode::Sanitized,
    ))->toThrow(InvalidSanitizerConfig::class);
});

test('neither removing nor masking is allowed in raw mode', function () {
    $sanitizer = new Sanitizer(
        sanitizerConfig(['remove_client_ip' => false, 'mask_client_ip' => false]),
        StorageMode::Raw,
    );

    expect($sanitizer)->toBeInstanceOf(Sanitizer::class);
});
