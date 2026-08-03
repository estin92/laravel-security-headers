<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use Estin92\SecurityHeaders\Exceptions\InvalidSanitizerConfig;
use Estin92\SecurityHeaders\Support\JsonObject;
use stdClass;

final class Sanitizer
{
    /**
     * The only body fields strip_query may touch, per report type.
     *
     * @var array<string, list<string>>
     */
    private const URL_BODY_FIELDS = [
        'csp-violation' => ['documentURL', 'blockedURL', 'sourceFile', 'referrer'],
        'coep' => [],
        'coop' => [],
        'network-error' => [],
    ];

    private const NEL_HEADER_FIELDS = ['request_headers', 'response_headers'];

    public function __construct(
        private readonly SanitizerConfig $config,
        private readonly StorageMode $mode,
    ) {
        if ($this->mode === StorageMode::Sanitized) {
            $this->guardConfig();
        }
    }

    public function sanitize(ReportSubmission $submission): SanitizerResult
    {
        $report = $submission->report;

        if ($this->mode === StorageMode::Raw) {
            return new SanitizerResult(
                $report->body,
                $report->url,
                $submission->clientIp,
                $submission->requestUserAgent,
                $report->reportedUserAgent,
                [],
            );
        }

        $actions = [];

        $body = $this->sanitizeBody($report, $actions);
        $url = $this->sanitizeUrl($report->url, ['url'], $actions);
        $clientIp = $this->sanitizeClientIp($submission->clientIp, $actions);
        $requestUserAgent = $this->sanitizeUserAgent(
            $submission->requestUserAgent,
            $this->config->removeRequestUserAgent,
            'request_user_agent',
            $actions,
        );
        $reportedUserAgent = $this->sanitizeUserAgent(
            $report->reportedUserAgent,
            $this->config->removeReportedUserAgent,
            'reported_user_agent',
            $actions,
        );

        return new SanitizerResult($body, $url, $clientIp, $requestUserAgent, $reportedUserAgent, $actions);
    }

    private function guardConfig(): void
    {
        if ($this->config->removeClientIp && $this->config->maskClientIp) {
            throw InvalidSanitizerConfig::removeAndMaskConflict();
        }

        if (! $this->config->removeClientIp && ! $this->config->maskClientIp) {
            throw InvalidSanitizerConfig::exactIpInSanitizedMode();
        }
    }

    /**
     * @param  list<array{path: list<string|int>, action: string}>  $actions
     */
    private function sanitizeBody(NormalizedReport $report, array &$actions): ?JsonObject
    {
        if ($report->body === null) {
            return null;
        }

        $body = $report->body->toNative();

        if ($this->config->removeNelHeaders) {
            foreach (self::NEL_HEADER_FIELDS as $field) {
                $this->removeBodyField($body, $field, 'remove_nel_headers', $actions);
            }
        }

        if ($this->config->removeSample) {
            $this->removeBodyField($body, 'sample', 'remove_sample', $actions);
        }

        if ($this->config->stripQuery) {
            foreach (self::URL_BODY_FIELDS[$report->type->value] ?? [] as $field) {
                $this->stripBodyFieldQuery($body, $field, $actions);
            }
        }

        return JsonObject::fromNative($body);
    }

    /**
     * @param  list<array{path: list<string|int>, action: string}>  $actions
     */
    private function removeBodyField(stdClass $body, string $field, string $action, array &$actions): void
    {
        if (! property_exists($body, $field)) {
            return;
        }

        unset($body->{$field});
        $actions[] = ['path' => ['body', $field], 'action' => $action];
    }

    /**
     * @param  list<array{path: list<string|int>, action: string}>  $actions
     */
    private function stripBodyFieldQuery(stdClass $body, string $field, array &$actions): void
    {
        if (! property_exists($body, $field) || ! is_string($body->{$field})) {
            return;
        }

        $stripped = $this->stripQuery($body->{$field});

        if ($stripped === $body->{$field}) {
            return;
        }

        $body->{$field} = $stripped;
        $actions[] = ['path' => ['body', $field], 'action' => 'strip_query'];
    }

    /**
     * @param  list<string|int>  $path
     * @param  list<array{path: list<string|int>, action: string}>  $actions
     */
    private function sanitizeUrl(?string $url, array $path, array &$actions): ?string
    {
        if (! $this->config->stripQuery || $url === null) {
            return $url;
        }

        $stripped = $this->stripQuery($url);

        if ($stripped === $url) {
            return $url;
        }

        $actions[] = ['path' => $path, 'action' => 'strip_query'];

        return $stripped;
    }

    /**
     * @param  list<array{path: list<string|int>, action: string}>  $actions
     */
    private function sanitizeClientIp(?string $clientIp, array &$actions): ?string
    {
        if ($clientIp === null) {
            return null;
        }

        if ($this->config->removeClientIp) {
            $actions[] = ['path' => ['client_ip'], 'action' => 'remove_client_ip'];

            return null;
        }

        $masked = $this->maskIp($clientIp);

        // If we meant to mask but can't, drop the IP rather than store it exact.
        if ($masked === null) {
            $actions[] = ['path' => ['client_ip'], 'action' => 'remove_client_ip'];

            return null;
        }

        // An address already on its network boundary masks to itself.
        if ($masked !== $clientIp) {
            $actions[] = ['path' => ['client_ip'], 'action' => 'mask_client_ip'];
        }

        return $masked;
    }

    /**
     * @param  list<array{path: list<string|int>, action: string}>  $actions
     */
    private function sanitizeUserAgent(?string $value, bool $remove, string $field, array &$actions): ?string
    {
        if (! $remove || $value === null) {
            return $value;
        }

        $actions[] = ['path' => [$field], 'action' => 'remove_'.$field];

        return null;
    }

    private function stripQuery(string $value): string
    {
        // Leaves CSP values like inline or eval alone
        $scheme = strtolower((string) parse_url($value, PHP_URL_SCHEME));

        if ($scheme !== 'http' && $scheme !== 'https') {
            return $value;
        }

        $queryStart = strpos($value, '?');

        return $queryStart === false ? $value : substr($value, 0, $queryStart);
    }

    private function maskIp(string $ip): ?string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $this->maskIpv4($ip);
        }

        $packed = inet_pton($ip);

        if ($packed === false || strlen($packed) !== 16) {
            return null;
        }

        return $this->maskIpv6($packed);
    }

    private function maskIpv4(string $ip): string
    {
        $octets = explode('.', $ip);
        $octets[3] = '0';

        return implode('.', $octets);
    }

    private function maskIpv6(string $packed): string
    {
        // Keep the first 48 bits (the /48 network), zero the remaining 80.
        $masked = substr($packed, 0, 6).str_repeat("\0", 10);

        return (string) inet_ntop($masked);
    }
}
