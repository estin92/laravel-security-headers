<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\NormalizedReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportSubmission;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Reporting\Ingestion\StoragePolicy;
use Estin92\SecurityHeaders\Support\JsonObject;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function makeReport(array $overrides = []): SecurityReport
{
    return SecurityReport::query()->create(array_merge([
        'type' => 'csp-violation',
        'protocol' => 'reporting-api',
        'url' => 'https://example.com/p',
        'url_origin' => 'https://example.com',
        'age' => 12,
        'reported_user_agent' => 'reported-UA',
        'request_user_agent' => 'request-UA',
        'client_ip' => null,
        'body' => JsonObject::fromNative((object) ['blockedURL' => 'https://evil.example/x']),
        'storage_mode' => 'sanitized',
        'sanitizer_version' => '1:'.str_repeat('a', 64),
        'sanitization_actions' => [['path' => ['client_ip'], 'action' => 'remove_client_ip']],
        'incident_fingerprint' => str_repeat('a', 64),
        'received_at' => '2026-08-03 00:00:00',
    ], $overrides));
}

test('a report round-trips through the database', function () {
    $created = makeReport();
    $found = SecurityReport::query()->findOrFail($created->id);

    expect($found->type)->toBe('csp-violation');
    expect($found->body)->toBeInstanceOf(JsonObject::class);
    expect($found->body->get(['blockedURL']))->toBe('https://evil.example/x');
});

test('the body cast keeps an empty object distinct from an empty list', function () {
    $emptyObject = makeReport(['body' => JsonObject::fromNative(json_decode('{}', false))]);
    $withList = makeReport(['body' => JsonObject::fromNative(json_decode('{"frames":[]}', false))]);

    expect(SecurityReport::query()->findOrFail($emptyObject->id)->body->toJson())->toBe('{}');
    expect(SecurityReport::query()->findOrFail($withList->id)->body->toJson())->toBe('{"frames":[]}');
});

test('a null body is stored and read back as null', function () {
    $created = makeReport(['body' => null]);

    expect(SecurityReport::query()->findOrFail($created->id)->body)->toBeNull();
});

test('nested object and list distinctions survive the round-trip', function () {
    $body = JsonObject::fromNative(json_decode('{"frames":[{"url":"a"}],"meta":{}}', false));
    $created = makeReport(['body' => $body]);

    $found = SecurityReport::query()->findOrFail($created->id);

    expect($found->body->toJson())->toBe('{"frames":[{"url":"a"}],"meta":{}}');
    expect($found->body->get(['frames', 0, 'url']))->toBe('a');
});

test('a stored null value is distinct from a missing path after the round-trip', function () {
    $body = JsonObject::fromNative(json_decode('{"present":null}', false));
    $created = makeReport(['body' => $body]);

    $found = SecurityReport::query()->findOrFail($created->id);

    expect($found->body->has(['present']))->toBeTrue();
    expect($found->body->get(['present']))->toBeNull();
    expect($found->body->has(['absent']))->toBeFalse();
});

test('a body read from the model cannot be mutated back into the stored value', function () {
    $created = makeReport();
    $found = SecurityReport::query()->findOrFail($created->id);

    $found->body->toNative()->blockedURL = 'mutated';

    expect(SecurityReport::query()->findOrFail($created->id)->body->get(['blockedURL']))
        ->toBe('https://evil.example/x');
});

test('the sanitization actions persist as a list of path and action', function () {
    $created = makeReport();
    $actions = SecurityReport::query()->findOrFail($created->id)->sanitization_actions;

    expect($actions)->toBe([['path' => ['client_ip'], 'action' => 'remove_client_ip']]);
});

test('an empty actions list round-trips as an empty list', function () {
    $created = makeReport(['sanitization_actions' => []]);

    expect(SecurityReport::query()->findOrFail($created->id)->sanitization_actions)->toBe([]);
});

test('the nullable columns accept null', function () {
    $created = makeReport(['url' => null, 'url_origin' => null, 'age' => null, 'client_ip' => null]);
    $found = SecurityReport::query()->findOrFail($created->id);

    expect($found->url)->toBeNull();
    expect($found->url_origin)->toBeNull();
    expect($found->age)->toBeNull();
});

test('the configured table name is honoured', function () {
    config()->set('security-headers.reporting.ingestion.database.table', 'security_reports');

    expect((new SecurityReport)->getTable())->toBe('security_reports');
});

test('a report built by the storage policy saves and reads back sanitized', function () {
    $config = [
        'storage' => [
            'mode' => 'sanitized',
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
    ];

    $report = new NormalizedReport(
        ReportType::CspViolation,
        'https://example.com/p?token=secret',
        12,
        'reported-UA',
        JsonObject::fromNative((object) ['blockedURL' => 'https://evil.example/x?s=1']),
        ReportProtocol::ReportingApi,
    );
    $submission = new ReportSubmission($report, new DateTimeImmutable('2026-08-03T00:00:00Z'), '203.0.113.9', 'request-UA');

    $model = (new StoragePolicy($config))->apply($submission);
    $model->save();

    $found = SecurityReport::query()->findOrFail($model->id);

    expect($found->url)->toBe('https://example.com/p');
    expect($found->url_origin)->toBe('https://example.com');
    expect($found->client_ip)->toBeNull();
    expect($found->body->get(['blockedURL']))->toBe('https://evil.example/x');
    expect($found->incident_fingerprint)->toMatch('/\A[0-9a-f]{64}\z/');
    expect($found->sanitization_actions)->toContain(['path' => ['client_ip'], 'action' => 'remove_client_ip']);
});
