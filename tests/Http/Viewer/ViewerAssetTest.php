<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;

beforeEach(function () {
    $dist = sys_get_temp_dir().'/sh-viewer-dist-'.bin2hex(random_bytes(6));
    File::ensureDirectoryExists($dist.'/.vite');
    File::ensureDirectoryExists($dist.'/assets');
    File::put($dist.'/.vite/manifest.json', json_encode([
        'resources/js/app.ts' => ['file' => 'assets/app-abc123.js', 'css' => ['assets/app-def456.css']],
    ]));
    File::put($dist.'/assets/app-abc123.js', 'console.log(1);');
    File::put($dist.'/assets/app-def456.css', 'body{}');

    config()->set('security-headers.reporting.viewer.dist_path', $dist);
    $this->dist = $dist;
});

afterEach(function () {
    File::deleteDirectory($this->dist);
});

test('a manifest-listed hashed asset is served with nosniff and immutable cache', function () {
    $response = $this->get('/security-headers/reports/assets/assets/app-abc123.js');

    $response->assertOk();
    expect($response->headers->get('X-Content-Type-Options'))->toBe('nosniff');
    expect($response->headers->get('Cache-Control'))->toContain('immutable');
    expect($response->headers->get('Content-Type'))->toContain('javascript');
});

test('a listed css asset is served as text/css', function () {
    $response = $this->get('/security-headers/reports/assets/assets/app-def456.css');

    $response->assertOk();
    expect($response->headers->get('Content-Type'))->toContain('css');
});

test('an unknown asset not in the manifest is rejected', function () {
    $this->get('/security-headers/reports/assets/assets/not-in-manifest.js')->assertNotFound();
});

test('a traversal attempt is rejected', function () {
    $this->get('/security-headers/reports/assets/..%2f..%2fconfig.php')->assertNotFound();
});

test('the asset route is public and not gated', function () {
    app()['env'] = 'production';

    $this->get('/security-headers/reports/assets/assets/app-abc123.js')->assertOk();
});
