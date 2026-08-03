<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting;

use Estin92\SecurityHeaders\Exceptions\InvalidReportingEndpoint;
use Estin92\SecurityHeaders\Support\TrustworthyLocalHost;

final readonly class ReportingEndpoint
{
    private function __construct(
        public string $name,
        public string $url,
        public ?string $legacyUrl,
    ) {}

    /**
     * @param  mixed  $definition  Unvalidated config for one endpoint.
     */
    public static function fromConfig(string $name, mixed $definition): self
    {
        self::guardName($name);

        $definition = is_array($definition) ? $definition : [];

        $url = $definition['url'] ?? null;

        if (! is_string($url) || $url === '') {
            throw InvalidReportingEndpoint::missingUrl($name);
        }

        self::guardUrl($url);

        $legacyUrl = $definition['legacy_url'] ?? null;

        if ($legacyUrl !== null) {
            $legacyUrl = is_string($legacyUrl) ? $legacyUrl : '';
            self::guardUrl($legacyUrl);
        }

        return new self($name, $url, $legacyUrl);
    }

    public function reportUri(): string
    {
        return $this->legacyUrl ?? $this->url;
    }

    private static function guardName(string $name): void
    {
        if (preg_match('/\A[a-z][a-z0-9-]*\z/', $name) !== 1) {
            throw InvalidReportingEndpoint::invalidName($name);
        }
    }

    private static function guardUrl(string $url): void
    {
        // This value goes straight into the report-uri directive, so a space,
        // semicolon or comma would let it break out into a new directive. Allow
        // only the characters that are valid in a url.
        if (preg_match('#\A[A-Za-z0-9\-._~:/?\#\[\]@!$&\'()*+=%]+\z#', $url) !== 1) {
            throw InvalidReportingEndpoint::injectionInValue($url);
        }

        // A % must start a valid two-digit escape.
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $url) === 1) {
            throw InvalidReportingEndpoint::malformedUrl($url);
        }

        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw InvalidReportingEndpoint::malformedUrl($url);
        }

        /** @var array{scheme: string, host: string, user?: string, pass?: string, fragment?: string} $parts */
        $parts = parse_url($url);

        $scheme = strtolower($parts['scheme']);

        if (! in_array($scheme, ['http', 'https'], true)) {
            throw InvalidReportingEndpoint::nonHttpUrl($url);
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw InvalidReportingEndpoint::urlHasCredentials($url);
        }

        if (isset($parts['fragment'])) {
            throw InvalidReportingEndpoint::urlHasFragment($url);
        }

        if ($scheme === 'http' && ! TrustworthyLocalHost::matches($parts['host'])) {
            throw InvalidReportingEndpoint::insecureUrl($url);
        }
    }
}
