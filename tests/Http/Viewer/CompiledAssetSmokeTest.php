<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Http\Viewer\ViewerAssets;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Gate;

beforeEach(function () {
    Gate::define('viewSecurityHeaderReports', fn (?Authenticatable $user) => true);
    config()->set('security-headers.csp.enforce.enabled', true);
});

test('the real committed dist build is present and its manifest names the entry', function () {
    $assets = new ViewerAssets;

    expect($assets->built())->toBeTrue();
    expect($assets->entryScript())->toStartWith('assets/app-')->toEndWith('.js');
    expect($assets->entryStyle())->toStartWith('assets/app-')->toEndWith('.css');
});

test('the shell boots the real compiled entry under the viewer CSP through the full stack', function () {
    $assets = new ViewerAssets;
    $script = $assets->entryScript();
    $style = $assets->entryStyle();

    $response = $this->get('/security-headers/reports');

    $response->assertOk();
    $response->assertSee($script, false);
    $response->assertSee($style, false);
    $response->assertSee('security-headers-viewer', false);

    $csp = (string) $response->headers->get('Content-Security-Policy');
    expect($csp)->toContain("default-src 'none'");
    expect($csp)->toContain("script-src 'self'");
    expect($csp)->not->toContain('unsafe-inline');
});

test('the real compiled script asset is served with nosniff and immutable cache', function () {
    $script = (new ViewerAssets)->entryScript();

    $response = $this->get("/security-headers/reports/assets/{$script}");

    $response->assertOk();
    expect($response->headers->get('Content-Type'))->toContain('javascript');
    expect($response->headers->get('X-Content-Type-Options'))->toBe('nosniff');
    expect($response->headers->get('Cache-Control'))->toContain('immutable');
});

test('the real compiled stylesheet asset is served as css', function () {
    $style = (new ViewerAssets)->entryStyle();

    $response = $this->get("/security-headers/reports/assets/{$style}");

    $response->assertOk();
    expect($response->headers->get('Content-Type'))->toContain('css');
});

test('the compiled bundle contains no inline script that would need a CSP nonce', function () {
    $response = $this->get('/security-headers/reports');

    $response->assertOk();
    $body = $response->getContent();

    // The only <script> tag must be the external module src, never an inline block.
    expect($body)->not->toMatch('/<script(?![^>]*\bsrc=)[^>]*>[^<]/');
});
