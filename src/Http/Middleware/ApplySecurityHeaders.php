<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Middleware;

use Closure;
use Estin92\SecurityHeaders\Csp\CspCompiler;
use Estin92\SecurityHeaders\Csp\CspPolicy;
use Estin92\SecurityHeaders\Csp\CspPolicyResolver;
use Estin92\SecurityHeaders\Headers\FlatHeaderCompiler;
use Estin92\SecurityHeaders\Headers\HstsCompiler;
use Estin92\SecurityHeaders\PermissionsPolicy\PermissionsPolicyCompiler;
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
        $enforce = $this->cspChannel('enforce');
        $reportOnly = $this->cspChannel('report_only');

        $requiresNonce = $enforce?->requiresNonce() === true
            || $reportOnly?->requiresNonce() === true;

        if ($requiresNonce) {
            Vite::useCspNonce();
        }

        $response = $next($request);

        $nonce = $requiresNonce ? Vite::cspNonce() : null;

        foreach ($this->flatHeaders()->compile() as $name => $value) {
            $response->headers->set($name, $value);
        }

        $hsts = $this->hsts()->compile();

        if ($hsts !== null) {
            $response->headers->set('Strict-Transport-Security', $hsts);
        }

        $permissionsPolicy = $this->permissionsPolicy();

        if ($permissionsPolicy !== null) {
            $response->headers->set('Permissions-Policy', $permissionsPolicy);
        }

        if ($enforce !== null) {
            $response->headers->set(
                'Content-Security-Policy',
                (new CspCompiler)->compile($enforce, $nonce),
            );
        }

        if ($reportOnly !== null) {
            $response->headers->set(
                'Content-Security-Policy-Report-Only',
                (new CspCompiler)->compile($reportOnly, $nonce),
            );
        }

        return $response;
    }

    private function flatHeaders(): FlatHeaderCompiler
    {
        $configured = config('security-headers.headers');

        return new FlatHeaderCompiler(is_array($configured) ? $configured : []);
    }

    private function hsts(): HstsCompiler
    {
        $configured = config('security-headers.hsts');

        return new HstsCompiler(is_array($configured) ? $configured : []);
    }

    private function permissionsPolicy(): ?string
    {
        if (config('security-headers.permissions_policy.enabled') !== true) {
            return null;
        }

        $features = config('security-headers.permissions_policy.features');

        return (new PermissionsPolicyCompiler)->compile(is_array($features) ? $features : []);
    }

    private function cspChannel(string $channel): ?CspPolicy
    {
        if (config("security-headers.csp.{$channel}.enabled") !== true) {
            return null;
        }

        return app(CspPolicyResolver::class)->resolve(config("security-headers.csp.{$channel}.policy"));
    }
}
