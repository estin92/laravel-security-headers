<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Middleware;

use Closure;
use Estin92\SecurityHeaders\Csp\CspCompiler;
use Estin92\SecurityHeaders\Csp\CspPolicy;
use Estin92\SecurityHeaders\Csp\CspPolicyResolver;
use Estin92\SecurityHeaders\Headers\Hsts;
use Estin92\SecurityHeaders\Headers\SimpleHeaders;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Vite;
use Symfony\Component\HttpFoundation\Response;

class ApplySecurityHeaders
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $policy = $this->cspPolicy();

        $requiresNonce = $policy?->requiresNonce() === true;

        if ($requiresNonce) {
            Vite::useCspNonce();
        }

        $response = $next($request);

        $nonce = $requiresNonce ? Vite::cspNonce() : null;

        foreach ($this->staticHeaders()->compile() as $name => $value) {
            $response->headers->set($name, $value);
        }

        $hsts = $this->hsts()->compile();

        if ($hsts !== null) {
            $response->headers->set('Strict-Transport-Security', $hsts);
        }

        if ($policy !== null) {
            $response->headers->set(
                'Content-Security-Policy',
                (new CspCompiler)->compile($policy, $nonce),
            );
        }

        return $response;
    }

    private function staticHeaders(): SimpleHeaders
    {
        $configured = config('security-headers.headers');

        return new SimpleHeaders(is_array($configured) ? $configured : []);
    }

    private function hsts(): Hsts
    {
        $configured = config('security-headers.hsts');

        return new Hsts(is_array($configured) ? $configured : []);
    }

    private function cspPolicy(): ?CspPolicy
    {
        if (config('security-headers.csp.enabled') !== true) {
            return null;
        }

        return app(CspPolicyResolver::class)->resolve(config('security-headers.csp.policy'));
    }
}
