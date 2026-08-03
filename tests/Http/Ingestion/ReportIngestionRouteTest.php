<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\IngestionStorageUnavailable;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

function reportsUrl(): string
{
    return '/security/reports';
}

function modernReport(): string
{
    return json_encode([[
        'type' => 'csp-violation',
        'age' => 10,
        'url' => 'https://example.com/p',
        'user_agent' => 'Mozilla/5.0',
        'body' => ['blockedURL' => 'https://evil.example/x'],
    ]], JSON_THROW_ON_ERROR);
}

test('a valid modern batch is accepted and stored', function () {
    $response = test()->call('POST', reportsUrl(), [], [], [], ['CONTENT_TYPE' => 'application/reports+json'], modernReport());

    $response->assertNoContent(204);
    expect(SecurityReport::query()->count())->toBe(1);
});

test('a preflight from an allowed origin returns 204 with the ACAO header', function () {
    config()->set('security-headers.reporting.ingestion.cors.allowed_origins', ['https://app.example.com']);

    $response = test()->call('OPTIONS', reportsUrl(), [], [], [], ['HTTP_ORIGIN' => 'https://app.example.com']);

    $response->assertNoContent(204);
    expect($response->headers->get('Access-Control-Allow-Origin'))->toBe('https://app.example.com');
});

test('a malformed body returns 400 with the stable error code', function () {
    $response = test()->call('POST', reportsUrl(), [], [], [], ['CONTENT_TYPE' => 'application/reports+json'], '[{');

    $response->assertStatus(400);
    $response->assertJson(['error' => 'malformed_json']);
});

test('an unsupported media type returns 415', function () {
    $response = test()->call('POST', reportsUrl(), [], [], [], ['CONTENT_TYPE' => 'text/plain'], '[]');

    $response->assertStatus(415);
    $response->assertJson(['error' => 'unsupported_media_type']);
});

test('the ingestion route is not in the web group', function () {
    $route = Route::getRoutes()->match(
        Request::create(reportsUrl(), 'POST', server: ['CONTENT_TYPE' => 'application/reports+json']),
    );

    expect($route->gatherMiddleware())->not->toContain('web');
});

test('the daily prune schedule is registered when the route is active', function () {
    $schedule = app(Schedule::class);

    $commands = array_map(fn ($event) => $event->command, $schedule->events());
    $prunes = array_filter($commands, fn ($command) => str_contains((string) $command, 'security-headers:prune-reports'));

    expect($prunes)->not->toBeEmpty();
});

test('a missing table returns 503 without disclosing the reason, and fires the operational event', function () {
    Event::fake([IngestionStorageUnavailable::class]);
    Schema::drop('security_reports');

    $response = test()->call('POST', reportsUrl(), [], [], [], ['CONTENT_TYPE' => 'application/reports+json'], modernReport());

    $response->assertStatus(503);
    $response->assertJson(['error' => 'service_unavailable']);
    Event::assertDispatched(IngestionStorageUnavailable::class);
});

test('the readiness check does not cache a missing table, so it recovers once the table returns', function () {
    Schema::rename('security_reports', 'security_reports_hidden');
    test()->call('POST', reportsUrl(), [], [], [], ['CONTENT_TYPE' => 'application/reports+json'], modernReport())
        ->assertStatus(503);

    Schema::rename('security_reports_hidden', 'security_reports');
    test()->call('POST', reportsUrl(), [], [], [], ['CONTENT_TYPE' => 'application/reports+json'], modernReport())
        ->assertNoContent(204);
});

test('an unreachable database fails closed with 503 rather than crashing', function () {
    config()->set('database.connections.broken', ['driver' => 'sqlite', 'database' => '/does/not/exist/reports.sqlite']);
    config()->set('security-headers.reporting.ingestion.database.connection', 'broken');

    $response = test()->call('POST', reportsUrl(), [], [], [], ['CONTENT_TYPE' => 'application/reports+json'], modernReport());

    $response->assertStatus(503);
    $response->assertJson(['error' => 'service_unavailable']);
});
