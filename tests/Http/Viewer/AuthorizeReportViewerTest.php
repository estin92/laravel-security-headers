<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Http\Middleware\Viewer\AuthorizeReportViewer;
use Estin92\SecurityHeaders\Http\Viewer\ViewerApiException;
use Illuminate\Http\Request;
use Illuminate\Routing\Route as RoutingRoute;
use Symfony\Component\HttpKernel\Exception\HttpException;

function requestNamed(string $name, string $uri = '/x'): Request
{
    $route = new RoutingRoute(['GET'], $uri, ['as' => $name]);
    $request = Request::create($uri);
    $request->setRouteResolver(fn () => $route);

    return $request;
}

test('on an API route a denial throws the self-rendering forbidden envelope exception', function () {
    app()['env'] = 'production';
    $request = requestNamed('security-headers.viewer.api.reports');

    expect(fn () => (new AuthorizeReportViewer)->handle($request, fn () => response('ok')))
        ->toThrow(ViewerApiException::class);
});

test('on the shell a denial aborts with a plain HTTP 403', function () {
    app()['env'] = 'production';
    $request = requestNamed('security-headers.viewer.shell');

    expect(fn () => (new AuthorizeReportViewer)->handle($request, fn () => response('ok')))
        ->toThrow(HttpException::class);
});

test('it passes through when the gate allows', function () {
    app()['env'] = 'local';
    $request = requestNamed('security-headers.viewer.api.reports');

    $response = (new AuthorizeReportViewer)->handle($request, fn () => response('ok'));

    expect($response->getContent())->toBe('ok');
});
