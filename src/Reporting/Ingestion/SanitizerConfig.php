<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

final readonly class SanitizerConfig
{
    public function __construct(
        public bool $removeClientIp,
        public bool $maskClientIp,
        public bool $stripQuery,
        public bool $removeSample,
        public bool $removeNelHeaders,
        public bool $removeRequestUserAgent,
        public bool $removeReportedUserAgent,
    ) {}

    /**
     * @param  array<mixed>  $config
     */
    public static function fromArray(array $config): self
    {
        return new self(
            (bool) ($config['remove_client_ip'] ?? false),
            (bool) ($config['mask_client_ip'] ?? false),
            (bool) ($config['strip_query'] ?? false),
            (bool) ($config['remove_sample'] ?? false),
            (bool) ($config['remove_nel_headers'] ?? false),
            (bool) ($config['remove_request_user_agent'] ?? false),
            (bool) ($config['remove_reported_user_agent'] ?? false),
        );
    }

    /**
     * The effective toggles in a fixed key order, so the same policy always
     * hashes the same regardless of how the source config was written.
     *
     * @return array<string, bool>
     */
    public function canonical(): array
    {
        return [
            'remove_client_ip' => $this->removeClientIp,
            'mask_client_ip' => $this->maskClientIp,
            'strip_query' => $this->stripQuery,
            'remove_sample' => $this->removeSample,
            'remove_nel_headers' => $this->removeNelHeaders,
            'remove_request_user_agent' => $this->removeRequestUserAgent,
            'remove_reported_user_agent' => $this->removeReportedUserAgent,
        ];
    }
}
