<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidIngestionConfig;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionConfigValidator;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;

function validIngestionConfig(array $overrides = []): array
{
    return array_replace_recursive([
        'enabled' => true,
        'report_type_enum' => ReportType::class,
        'body_validators' => [],
        'storage' => [
            'mode' => 'sanitized',
            'raw_acknowledged' => false,
            'sanitizers' => [
                'remove_client_ip' => true,
                'mask_client_ip' => false,
                'strip_query' => true,
                'remove_sample' => false,
                'remove_nel_headers' => true,
                'remove_request_user_agent' => false,
                'remove_reported_user_agent' => false,
            ],
        ],
        'limits' => [
            'max_bytes' => 65536,
            'max_reports_per_batch' => 100,
            'json_depth' => 32,
            'url_length' => 8192,
            'user_agent_length' => 1024,
            'relaxed_acknowledged' => false,
        ],
        'rate_limiting' => [
            'enabled' => true,
            'limiter' => 'security-headers-ingestion',
            'reporting_api_per_minute' => 120,
            'legacy_csp_per_minute' => 600,
            'external_limiting_acknowledged' => false,
        ],
        'cors' => ['allowed_origins' => []],
        'retention' => ['days' => 30, 'max_rows' => 100000],
    ], $overrides);
}

function validate(array $config): void
{
    (new IngestionConfigValidator)->validate($config);
}

test('the shipped default config validates clean', function () {
    $config = config('security-headers.reporting.ingestion');

    validate($config);
})->throwsNoExceptions();

test('a hand-built valid config validates clean', function () {
    validate(validIngestionConfig());
})->throwsNoExceptions();

test('a limit over its hard ceiling is rejected', function (string $key, int $tooBig) {
    expect(fn () => validate(validIngestionConfig(['limits' => [$key => $tooBig]])))
        ->toThrow(InvalidIngestionConfig::class);
})->with([
    'max_bytes' => ['max_bytes', 1048577],
    'max_reports_per_batch' => ['max_reports_per_batch', 10001],
    'json_depth' => ['json_depth', 129],
    'url_length' => ['url_length', 65537],
    'user_agent_length' => ['user_agent_length', 8193],
]);

test('a non-positive limit is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['limits' => ['max_bytes' => 0]])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('an unknown storage mode is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['storage' => ['mode' => 'wibble']])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('a non-boolean sanitizer toggle is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['storage' => ['sanitizers' => ['strip_query' => 'yes']]])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('a non-boolean acknowledgement flag is rejected', function (array $override) {
    expect(fn () => validate(validIngestionConfig($override)))
        ->toThrow(InvalidIngestionConfig::class);
})->with([
    'raw_acknowledged string' => [['storage' => ['raw_acknowledged' => 'yes please']]],
    'relaxed_acknowledged int' => [['limits' => ['relaxed_acknowledged' => 1]]],
    'external_limiting_acknowledged null' => [['rate_limiting' => ['external_limiting_acknowledged' => null]]],
]);

test('a missing acknowledgement flag is rejected', function () {
    $config = validIngestionConfig();
    unset($config['storage']['raw_acknowledged']);

    expect(fn () => validate($config))->toThrow(InvalidIngestionConfig::class);
});

test('both true and false are accepted for an acknowledgement flag', function (bool $value) {
    validate(validIngestionConfig(['storage' => ['raw_acknowledged' => $value]]));
})->throwsNoExceptions()->with([true, false]);

test('the sanitizer remove-and-mask conflict is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['storage' => ['sanitizers' => ['remove_client_ip' => true, 'mask_client_ip' => true]]])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('the sanitized exact-IP loophole is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['storage' => ['sanitizers' => ['remove_client_ip' => false, 'mask_client_ip' => false]]])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('a rate limit of zero is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['rate_limiting' => ['reporting_api_per_minute' => 0]])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('a non-positive retention window is rejected', function (string $key) {
    expect(fn () => validate(validIngestionConfig(['retention' => [$key => 0]])))
        ->toThrow(InvalidIngestionConfig::class);
})->with(['days', 'max_rows']);

test('a retention row cap over its ceiling is rejected with a message stating the bound', function () {
    expect(fn () => validate(validIngestionConfig(['retention' => ['max_rows' => 5000001]])))
        ->toThrow(InvalidIngestionConfig::class, 'must be an integer between 1 and 5000000');
});

test('an invalid report_type_enum is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['report_type_enum' => 'NotAnEnum'])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('a body_validators entry for a built-in type is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['body_validators' => ['csp-violation' => 'AnyClass']])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('a malformed CORS origin is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['cors' => ['allowed_origins' => ['not a url']]])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('a disallowed http CORS origin that is not local is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['cors' => ['allowed_origins' => ['http://example.com']]])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('a valid https and local CORS origin is accepted', function () {
    validate(validIngestionConfig(['cors' => ['allowed_origins' => ['https://app.example.com', 'http://localhost:3000']]]));
})->throwsNoExceptions();

test('a CORS origin carrying a path is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['cors' => ['allowed_origins' => ['https://app.example.com/path']]])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('a report_type_enum that is not a string is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['report_type_enum' => 123])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('a body_validators value that is not an array is rejected', function () {
    expect(fn () => validate(validIngestionConfig(['body_validators' => 'nope'])))
        ->toThrow(InvalidIngestionConfig::class);
});

test('a config missing the rate settings still validates', function () {
    $config = validIngestionConfig();
    unset($config['rate_limiting']['reporting_api_per_minute'], $config['rate_limiting']['legacy_csp_per_minute']);

    validate($config);
})->throwsNoExceptions();
