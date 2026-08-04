<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Gate;

uses(RefreshDatabase::class);

dataset('viewer endpoints', [
    'shell' => ['/security-headers/reports'],
    'api' => ['/security-headers/reports/api/reports'],
]);

test('no ability defined in local allows even a guest', function (string $uri) {
    app()['env'] = 'local';

    expect($this->get($uri)->status())->not->toBe(403);
})->with('viewer endpoints');

test('no ability defined in production is denied', function (string $uri) {
    app()['env'] = 'production';

    $this->get($uri)->assertForbidden();
})->with('viewer endpoints');

test('a defined ability that denies is denied everywhere, local included', function (string $uri) {
    app()['env'] = 'local';
    Gate::define('viewSecurityHeaderReports', fn (?Authenticatable $user) => false);

    $this->get($uri)->assertForbidden();
})->with('viewer endpoints');

test('a defined ability that denies is denied in production too', function (string $uri) {
    app()['env'] = 'production';
    Gate::define('viewSecurityHeaderReports', fn (?Authenticatable $user) => false);

    $this->get($uri)->assertForbidden();
})->with('viewer endpoints');

test('a defined ability that allows an authenticated user is allowed', function (string $uri) {
    app()['env'] = 'production';
    Gate::define('viewSecurityHeaderReports', fn (?Authenticatable $user) => $user !== null);

    expect($this->actingAs(fakeViewer())->get($uri)->status())->not->toBe(403);
})->with('viewer endpoints');

test('the api denial renders the JSON envelope while the shell denial renders HTML', function () {
    app()['env'] = 'production';

    $this->getJson('/security-headers/reports/api/reports')
        ->assertForbidden()
        ->assertJson(['error' => 'forbidden']);

    $shell = $this->get('/security-headers/reports')->assertForbidden();
    expect($shell->headers->get('Content-Type'))->toContain('text/html');
});
