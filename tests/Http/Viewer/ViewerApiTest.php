<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Support\JsonObject;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Gate;

uses(RefreshDatabase::class);

beforeEach(function () {
    Gate::define('viewSecurityHeaderReports', fn (?Authenticatable $user) => true);
});

function makeApiReport(array $overrides = []): SecurityReport
{
    return SecurityReport::query()->create(array_merge([
        'type' => 'csp-violation',
        'protocol' => 'reporting-api',
        'url' => 'https://example.com/p',
        'url_origin' => 'https://example.com',
        'age' => 12,
        'reported_user_agent' => null,
        'request_user_agent' => 'request-UA',
        'client_ip' => null,
        'body' => JsonObject::fromNative((object) ['blockedURL' => 'https://evil.example/x']),
        'storage_mode' => 'sanitized',
        'sanitizer_version' => 'pkg-0.1.0:cfg-abc123',
        'sanitization_actions' => [],
        'incident_fingerprint' => str_repeat('a', 64),
        'received_at' => '2026-08-03 00:00:00',
    ], $overrides));
}

test('the feed returns reports newest-first with an opaque cursor field', function () {
    makeApiReport(['received_at' => '2026-08-01 00:00:00']);
    makeApiReport(['received_at' => '2026-08-03 00:00:00']);

    $response = $this->getJson('/security-headers/reports/api/reports');

    $response->assertOk();
    $response->assertJsonStructure(['data', 'next_cursor']);
    $received = array_column($response->json('data'), 'received_at');
    expect($received[0])->toBe('2026-08-03T00:00:00Z');
});

test('a second page follows the opaque cursor without overlap', function () {
    foreach (range(1, 5) as $day) {
        makeApiReport(['received_at' => sprintf('2026-08-0%d 00:00:00', $day)]);
    }

    $first = $this->getJson('/security-headers/reports/api/reports?limit=2')->assertOk();
    $cursor = $first->json('next_cursor');
    expect($cursor)->not->toBeNull();

    $second = $this->getJson('/security-headers/reports/api/reports?limit=2&cursor='.urlencode($cursor))->assertOk();

    $firstIds = collect($first->json('data'))->pluck('id');
    $secondIds = collect($second->json('data'))->pluck('id');
    expect($firstIds->intersect($secondIds)->all())->toBe([]);
});

test('a malformed cursor yields 422 invalid_cursor', function () {
    $this->getJson('/security-headers/reports/api/reports?cursor=!!!notacursor')
        ->assertStatus(422)
        ->assertJson(['error' => 'invalid_cursor']);
});

test('an over-large limit is clamped to the max page size, not honoured or rejected', function () {
    foreach (range(1, 150) as $i) {
        makeApiReport(['incident_fingerprint' => str_pad((string) $i, 64, '0', STR_PAD_LEFT)]);
    }

    $response = $this->getJson('/security-headers/reports/api/reports?limit=1000000')->assertOk();

    expect(count($response->json('data')))->toBe(100);
});

test('an unknown filter yields 422 invalid_filter', function () {
    $this->getJson('/security-headers/reports/api/reports?bogus=1')
        ->assertStatus(422)
        ->assertJson(['error' => 'invalid_filter']);
});

test('a bad fingerprint yields 422 invalid_fingerprint', function () {
    $this->getJson('/security-headers/reports/api/incidents/NOThex')
        ->assertStatus(422)
        ->assertJson(['error' => 'invalid_fingerprint']);
});

test('a detail request for a pruned report yields 404 not_found', function () {
    $this->getJson('/security-headers/reports/api/reports/999999')
        ->assertStatus(404)
        ->assertJson(['error' => 'not_found']);
});

test('the detail response carries the tree, provenance, and only displayed fields', function () {
    $report = makeApiReport(['sanitizer_version' => 'pkg-0.1.0:cfg-abc123']);

    $response = $this->getJson("/security-headers/reports/api/reports/{$report->id}");

    $response->assertOk();
    $response->assertJsonStructure(['data' => [
        'tree' => [['path', 'key', 'state', 'value', 'value_type', 'action', 'children']],
        'context' => ['type', 'protocol', 'received_at', 'incident_fingerprint'],
        'raw_mode',
        'provenance' => ['sanitizer_version', 'label'],
    ]]);
    $response->assertJsonPath('data.provenance.sanitizer_version', 'pkg-0.1.0:cfg-abc123');
    expect($response->json('data.raw_mode'))->toBeFalse();
});

test('a raw-mode report exposes a prominent raw warning flag even with no actions', function () {
    $report = makeApiReport(['storage_mode' => 'raw', 'sanitization_actions' => []]);

    $response = $this->getJson("/security-headers/reports/api/reports/{$report->id}")->assertOk();

    expect($response->json('data.raw_mode'))->toBeTrue();
    expect($response->json('data.raw_warning'))->toBeTrue();
});

test('incidents drill-through returns the reports sharing a fingerprint', function () {
    $fingerprint = str_repeat('b', 64);
    makeApiReport(['incident_fingerprint' => $fingerprint]);
    makeApiReport(['incident_fingerprint' => $fingerprint]);
    makeApiReport(['incident_fingerprint' => str_repeat('c', 64)]);

    $response = $this->getJson("/security-headers/reports/api/incidents/{$fingerprint}")->assertOk();

    expect(count($response->json('data')))->toBe(2);
});

test('the filters endpoint returns bounded type and protocol values', function () {
    makeApiReport(['type' => 'csp-violation']);
    makeApiReport(['type' => 'network-error']);

    $response = $this->getJson('/security-headers/reports/api/filters')->assertOk();

    $response->assertJsonStructure(['type', 'protocol', 'url_origin', 'url_origin_truncated']);
    expect($response->json('type'))->toEqualCanonicalizing(['csp-violation', 'network-error']);
});
