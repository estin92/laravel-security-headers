<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Middleware\Viewer;

use Closure;
use Estin92\SecurityHeaders\Http\Viewer\ViewerApiException;
use Estin92\SecurityHeaders\Http\Viewer\ViewerGate;
use Estin92\SecurityHeaders\Http\Viewer\ViewerRoutes;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class AuthorizeReportViewer
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (ViewerGate::allows($request->user())) {
            return $next($request);
        }

        if ($request->routeIs(ViewerRoutes::API_WILDCARD)) {
            throw ViewerApiException::forbidden();
        }

        abort(403);
    }
}
