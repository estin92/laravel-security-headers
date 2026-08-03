<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\SecurityHeadersServiceProvider;
use Estin92\SecurityHeaders\Support\UrlOrigin;

final class StoragePolicy
{
    private readonly SanitizerConfig $sanitizerConfig;

    private readonly StorageMode $mode;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(array $config)
    {
        $storage = is_array($config['storage'] ?? null) ? $config['storage'] : [];
        $sanitizers = is_array($storage['sanitizers'] ?? null) ? $storage['sanitizers'] : [];

        $this->sanitizerConfig = SanitizerConfig::fromArray($sanitizers);
        $this->mode = StorageMode::from(is_string($storage['mode'] ?? null) ? $storage['mode'] : 'sanitized');
    }

    public function apply(ReportSubmission $submission): SecurityReport
    {
        $report = $submission->report;
        $result = (new Sanitizer($this->sanitizerConfig, $this->mode))->sanitize($submission);

        $version = $this->sanitizerVersion();
        $urlOrigin = UrlOrigin::from($result->url);

        $fingerprint = IncidentFingerprint::for(
            $report->type,
            $report->protocol,
            $result->url,
            $result->body,
            $this->mode,
            $version,
        );

        $model = new SecurityReport;
        $model->type = (string) $report->type->value;
        $model->protocol = $report->protocol->value;
        $model->url = $result->url;
        $model->url_origin = $urlOrigin;
        $model->age = $report->age;
        $model->reported_user_agent = $result->reportedUserAgent;
        $model->request_user_agent = $result->requestUserAgent;
        $model->client_ip = $result->clientIp;
        $model->body = $result->body;
        $model->storage_mode = $this->mode->value;
        $model->sanitizer_version = $version;
        $model->sanitization_actions = $result->actions;
        $model->incident_fingerprint = $fingerprint;
        $model->received_at = $submission->receivedAt;

        return $model;
    }

    private function sanitizerVersion(): string
    {
        $version = SecurityHeadersServiceProvider::VERSION;

        if ($this->mode === StorageMode::Raw) {
            return $version.':raw';
        }

        $hash = hash('sha256', (string) json_encode($this->sanitizerConfig->canonical(), JSON_THROW_ON_ERROR));

        return $version.':'.$hash;
    }
}
