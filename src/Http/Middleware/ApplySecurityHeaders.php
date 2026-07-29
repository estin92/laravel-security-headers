<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Middleware;

use Closure;
use Estin92\SecurityHeaders\Headers\SimpleHeaders;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ApplySecurityHeaders
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $configured = config('security-headers.headers');

        $headers = new SimpleHeaders(is_array($configured) ? $configured : []);

        foreach ($headers->compile() as $name => $value) {
            $response->headers->set($name, $value);
        }

        return $response;
    }
}
