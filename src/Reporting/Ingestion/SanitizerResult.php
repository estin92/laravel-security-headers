<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use Estin92\SecurityHeaders\Support\JsonObject;

final readonly class SanitizerResult
{
    /**
     * @param  list<array{path: list<string|int>, action: string}>  $actions
     */
    public function __construct(
        public ?JsonObject $body,
        public ?string $url,
        public ?string $clientIp,
        public ?string $requestUserAgent,
        public ?string $reportedUserAgent,
        public array $actions,
    ) {}
}
