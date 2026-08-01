<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Middleware;

use Closure;
use Estin92\SecurityHeaders\Coep\CoepCompiler;
use Estin92\SecurityHeaders\Coep\CoepReporting;
use Estin92\SecurityHeaders\Csp\CspCompiler;
use Estin92\SecurityHeaders\Csp\CspPolicy;
use Estin92\SecurityHeaders\Csp\CspPolicyResolver;
use Estin92\SecurityHeaders\Csp\CspReporting;
use Estin92\SecurityHeaders\Exceptions\InvalidCoep;
use Estin92\SecurityHeaders\Exceptions\InvalidNel;
use Estin92\SecurityHeaders\Exceptions\InvalidReportingEndpoint;
use Estin92\SecurityHeaders\Exceptions\InvalidReportToGroup;
use Estin92\SecurityHeaders\Headers\FlatHeaderCompiler;
use Estin92\SecurityHeaders\Headers\HstsCompiler;
use Estin92\SecurityHeaders\Nel\NelCompiler;
use Estin92\SecurityHeaders\Nel\NelPolicy;
use Estin92\SecurityHeaders\PermissionsPolicy\PermissionsPolicyCompiler;
use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;
use Estin92\SecurityHeaders\Reporting\ReportingEndpointsCompiler;
use Estin92\SecurityHeaders\Reporting\ReportToCompiler;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Vite;
use Symfony\Component\HttpFoundation\Response;

class ApplySecurityHeaders
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $skipCsp = config('security-headers.csp.skip_when_vite_hot') === true && Vite::isRunningHot();

        $channels = $skipCsp ? [] : array_filter([
            $this->resolveChannel('enforce', 'Content-Security-Policy'),
            $this->resolveChannel('report_only', 'Content-Security-Policy-Report-Only'),
        ]);

        $coepChannels = array_filter([
            $this->coepChannel('enforce', 'Cross-Origin-Embedder-Policy'),
            $this->coepChannel('report_only', 'Cross-Origin-Embedder-Policy-Report-Only'),
        ]);

        $nelDefinition = config('security-headers.nel');
        $nel = is_array($nelDefinition) && ($nelDefinition['enabled'] ?? false) === true
            ? NelPolicy::fromConfig(Arr::except($nelDefinition, ['enabled']))
            : null;

        $nelGroup = null;
        $nelGroupRecord = null;
        if ($nel !== null && $nel->reportToGroupKey !== null) {
            $nelGroup = $this->resolveNelGroup($nel->reportToGroupKey);
            $nel->assertCompatibleWith($nelGroup);
            $nelGroupRecord = ['key' => $nel->reportToGroupKey, 'group' => $nelGroup];
        }

        $requiresNonce = false;

        foreach ($channels as $channel) {
            $requiresNonce = $requiresNonce || $channel['policy']->requiresNonce();
        }

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

        foreach ($channels as $channel) {
            $response->headers->set(
                $channel['header'],
                (new CspCompiler)->compile($channel['policy'], $nonce, $channel['reporting']),
            );
        }

        foreach ($coepChannels as $coep) {
            $response->headers->set(
                $coep['header'],
                (new CoepCompiler)->compile($coep['value'], $coep['reporting']),
            );
        }

        $reportingHeader = $this->reportingEndpointsHeader(
            ...array_column($channels, 'endpoint'),
            ...array_column($coepChannels, 'endpoint'),
        );

        if ($reportingHeader !== null) {
            $response->headers->set('Reporting-Endpoints', $reportingHeader);
        }

        $groups = $this->reportToGroups(
            ...array_column($channels, 'group'),
            ...array_column($coepChannels, 'group'),
            ...($nelGroupRecord !== null ? [$nelGroupRecord] : []),
        );

        if ($groups !== []) {
            $response->headers->set('Report-To', (new ReportToCompiler)->compile($groups));
        }

        if ($nel !== null) {
            $response->headers->set('NEL', (new NelCompiler)->compile($nel, $nelGroup));
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

    /**
     * @return array{policy: CspPolicy, reporting: ?CspReporting, endpoint: ?ReportingEndpoint, group: ?array{key: string, group: ReportToGroup}, header: string}|null
     */
    private function resolveChannel(string $channel, string $header): ?array
    {
        $policy = $this->cspChannel($channel);

        if ($policy === null) {
            return null;
        }

        $endpoint = $this->reportingEndpoint("csp.{$channel}");
        $group = $this->reportToGroup("csp.{$channel}");
        $legacy = $group['group'] ?? null;

        return [
            'policy' => $policy,
            'reporting' => $endpoint !== null || $legacy !== null
                ? CspReporting::fromTargets($endpoint, $legacy, $this->emitLegacy("csp.{$channel}"))
                : null,
            'endpoint' => $endpoint,
            'group' => $group,
            'header' => $header,
        ];
    }

    private function cspChannel(string $channel): ?CspPolicy
    {
        if (config("security-headers.csp.{$channel}.enabled") !== true) {
            return null;
        }

        return app(CspPolicyResolver::class)->resolve(config("security-headers.csp.{$channel}.policy"));
    }

    /**
     * @return array{value: mixed, endpoint: ?ReportingEndpoint, reporting: ?CoepReporting, group: ?array{key: string, group: ReportToGroup}, header: string}|null
     */
    private function coepChannel(string $channel, string $header): ?array
    {
        if (config("security-headers.coep.{$channel}.enabled") !== true) {
            return null;
        }

        $endpoint = $this->reportingEndpoint("coep.{$channel}");

        if ($channel === 'report_only' && $endpoint === null) {
            throw InvalidCoep::reportOnlyMissingEndpoint();
        }

        $group = $this->reportToGroup("coep.{$channel}");
        $legacy = $group['group'] ?? null;

        return [
            'value' => config("security-headers.coep.{$channel}.value"),
            'endpoint' => $endpoint,
            'reporting' => $endpoint !== null || $legacy !== null ? CoepReporting::fromTargets($endpoint, $legacy) : null,
            'group' => $group,
            'header' => $header,
        ];
    }

    private function reportingEndpoint(string $configPath): ?ReportingEndpoint
    {
        $reference = config("security-headers.{$configPath}.reporting_endpoint");

        if ($reference === null) {
            return null;
        }

        if (! is_string($reference)) {
            throw InvalidReportingEndpoint::invalidReference($configPath, $reference);
        }

        $registry = config('security-headers.reporting.endpoints');
        $registry = is_array($registry) ? $registry : [];

        if (! array_key_exists($reference, $registry)) {
            throw InvalidReportingEndpoint::unknownReference($reference);
        }

        return ReportingEndpoint::fromConfig($reference, $registry[$reference]);
    }

    private function emitLegacy(string $configPath): bool
    {
        return filter_var(
            config("security-headers.{$configPath}.emit_legacy_report_uri", true),
            FILTER_VALIDATE_BOOL,
        );
    }

    /**
     * @return array{key: string, group: ReportToGroup}|null
     */
    private function reportToGroup(string $configPath): ?array
    {
        $reference = config("security-headers.{$configPath}.report_to_group");

        if ($reference === null) {
            return null;
        }

        if (! is_string($reference)) {
            throw InvalidReportToGroup::invalidReference($configPath, $reference);
        }

        return ['key' => $reference, 'group' => $this->resolveGroup($reference)];
    }

    private function resolveGroup(string $reference): ReportToGroup
    {
        $registry = config('security-headers.reporting.report_to_groups');
        $registry = is_array($registry) ? $registry : [];

        if (! array_key_exists($reference, $registry)) {
            throw InvalidReportToGroup::unknownGroup($reference);
        }

        $endpoints = config('security-headers.reporting.endpoints');
        $endpoints = is_array($endpoints) ? $endpoints : [];

        return ReportToGroup::fromConfig($reference, $registry[$reference], $endpoints);
    }

    private function resolveNelGroup(string $key): ReportToGroup
    {
        $registry = config('security-headers.reporting.report_to_groups');
        $registry = is_array($registry) ? $registry : [];

        if (! array_key_exists($key, $registry)) {
            throw InvalidNel::unknownGroup($key);
        }

        return $this->resolveGroup($key);
    }

    private function reportingEndpointsHeader(?ReportingEndpoint ...$endpoints): ?string
    {
        $unique = [];

        foreach ($endpoints as $endpoint) {
            if ($endpoint !== null) {
                $unique[$endpoint->name] = $endpoint;
            }
        }

        if ($unique === []) {
            return null;
        }

        return (new ReportingEndpointsCompiler)->compile($unique);
    }

    /**
     * @param  array{key: string, group: ReportToGroup}|null  ...$referenced
     * @return array<string, ReportToGroup>
     */
    private function reportToGroups(?array ...$referenced): array
    {
        $byKey = [];

        foreach ($referenced as $entry) {
            if ($entry !== null) {
                $byKey[$entry['key']] = $entry['group'];
            }
        }

        foreach ($this->removalCandidates() as $key) {
            if (! array_key_exists($key, $byKey)) {
                $byKey[$key] = $this->resolveGroup($key);
            }
        }

        $byName = [];

        foreach ($byKey as $group) {
            if (array_key_exists($group->group, $byName)) {
                throw InvalidReportToGroup::duplicateEmittedName($group->group);
            }

            $byName[$group->group] = $group;
        }

        return $byName;
    }

    /**
     * @return list<string>
     */
    private function removalCandidates(): array
    {
        $registry = config('security-headers.reporting.report_to_groups');
        $registry = is_array($registry) ? $registry : [];

        $keys = [];

        foreach ($registry as $key => $definition) {
            $maxAge = is_array($definition) ? ($definition['max_age'] ?? null) : null;

            if (($maxAge === 0 || $maxAge === '0') && is_string($key)) {
                $keys[] = $key;
            }
        }

        return $keys;
    }
}
