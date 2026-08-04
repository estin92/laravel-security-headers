<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Log;

beforeEach(function () {
    Gate::define('viewSecurityHeaderReports', fn (?Authenticatable $user) => true);
    config()->set('security-headers.reporting.viewer.dist_path', sys_get_temp_dir().'/sh-viewer-absent-'.bin2hex(random_bytes(6)));
});

test('in local a missing dist build returns an actionable HTML 500 and logs the fixed message', function () {
    app()['env'] = 'local';
    Log::spy();

    $response = $this->get('/security-headers/reports');

    $response->assertStatus(500);
    expect($response->getContent())->not->toContain('app-');
    expect($response->getContent())->toContain('build');
    Log::shouldHaveReceived('error')->withArgs(fn ($message) => str_contains($message, 'build'))->atLeast()->once();
});

test('in production a missing dist build returns a generic HTML 500 but still logs the fixed message', function () {
    app()['env'] = 'production';
    Log::spy();

    $response = $this->get('/security-headers/reports');

    $response->assertStatus(500);
    expect($response->getContent())->not->toContain('app-');
    expect($response->getContent())->not->toContain('npm');
    Log::shouldHaveReceived('error')->withArgs(fn ($message) => str_contains($message, 'build'))->atLeast()->once();
});

test('the shell route is gated like the api', function () {
    Gate::define('viewSecurityHeaderReports', fn ($user) => false);
    app()['env'] = 'production';

    $this->get('/security-headers/reports')->assertStatus(403);
});
