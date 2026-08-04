<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Viewer;

use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Reporting\Presentation\ResolverCaps;
use Estin92\SecurityHeaders\Reporting\Presentation\StateResolver;

final class ReportDetailPresenter
{
    public function __construct(
        private readonly StateResolver $resolver,
        private readonly ResolverCaps $caps,
    ) {}

    /**
     * @return array{
     *     id: int,
     *     tree: list<array<string, mixed>>,
     *     context: array<string, mixed>,
     *     raw_mode: bool,
     *     raw_warning: bool,
     *     provenance: array{sanitizer_version: string, label: string}
     * }
     */
    public function present(SecurityReport $report): array
    {
        $isRaw = $report->storage_mode === 'raw';

        return [
            'id' => $report->id,
            'tree' => array_map(
                static fn ($node): array => $node->toArray(),
                $this->resolver->resolve($report, $this->caps),
            ),
            'context' => [
                'type' => $report->type,
                'protocol' => $report->protocol,
                'url_origin' => $report->url_origin,
                'age' => $report->age,
                'received_at' => $report->received_at->toIso8601ZuluString(),
                'incident_fingerprint' => $report->incident_fingerprint,
            ],
            'raw_mode' => $isRaw,
            'raw_warning' => $isRaw,
            'provenance' => [
                'sanitizer_version' => $report->sanitizer_version,
                'label' => $this->provenanceLabel($report->sanitizer_version),
            ],
        ];
    }

    private function provenanceLabel(string $sanitizerVersion): string
    {
        return "Sanitized by security-headers ({$sanitizerVersion})";
    }
}
