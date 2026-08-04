<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Gate;

beforeEach(function () {
    Gate::define('viewSecurityHeaderReports', fn (?Authenticatable $user) => true);
    config()->set('security-headers.csp.enforce.enabled', true);
});

function assertViewerCsp(?string $csp): void
{
    expect($csp)->toContain("default-src 'none'");
    expect($csp)->toContain("script-src 'self'");
    expect($csp)->toContain("style-src 'self'");
    expect($csp)->toContain("connect-src 'self'");
    expect($csp)->toContain("img-src 'self'");
    expect($csp)->toContain("object-src 'none'");
    expect($csp)->toContain("base-uri 'none'");
    expect($csp)->toContain("frame-ancestors 'none'");
    expect($csp)->toContain("form-action 'none'");
    expect($csp)->not->toContain('unsafe-inline');
    expect($csp)->not->toContain('upgrade-insecure-requests');
}

test('the viewer authors the shell CSP on the real stack, even when the build is missing', function () {
    assertViewerCsp($this->get('/security-headers/reports')->headers->get('Content-Security-Policy'));
});

test('the viewer CSP is present on a fully rendered shell, not just the error page', function () {
    $dist = sys_get_temp_dir().'/sh-viewer-csp-'.bin2hex(random_bytes(6));
    File::ensureDirectoryExists($dist.'/.vite');
    File::ensureDirectoryExists($dist.'/assets');
    File::put($dist.'/.vite/manifest.json', json_encode([
        'resources/js/app.ts' => ['file' => 'assets/app-abc123.js', 'css' => ['assets/app-def456.css']],
    ]));
    config()->set('security-headers.reporting.viewer.dist_path', $dist);

    $response = $this->get('/security-headers/reports');

    $response->assertOk();
    expect($response->getContent())->toContain('assets/app-abc123.js');
    assertViewerCsp($response->headers->get('Content-Security-Policy'));

    File::deleteDirectory($dist);
});
