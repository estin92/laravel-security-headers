<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Controllers\Viewer;

use Estin92\SecurityHeaders\Http\Viewer\CursorCodec;
use Estin92\SecurityHeaders\Http\Viewer\PageLimit;
use Estin92\SecurityHeaders\Http\Viewer\ReportFilters;
use Estin92\SecurityHeaders\Models\SecurityReport;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class ReportFeedController
{
    public function __construct(private readonly ReportFilters $filters) {}

    public function __invoke(Request $request): JsonResponse
    {
        $query = SecurityReport::query()
            ->orderByDesc('received_at')
            ->orderByDesc('id');

        $this->filters->applyTo($query, $request->except(['limit', 'cursor']));

        $page = CursorCodec::paginate($query, PageLimit::from($request->query('limit')), $request->query('cursor'));

        return new JsonResponse([
            'data' => $page->items->map(fn (SecurityReport $report): array => $this->summary($report)),
            'next_cursor' => $page->nextCursor,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(SecurityReport $report): array
    {
        return [
            'id' => $report->id,
            'type' => $report->type,
            'protocol' => $report->protocol,
            'url_origin' => $report->url_origin,
            'received_at' => $report->received_at->toIso8601ZuluString(),
            'incident_fingerprint' => $report->incident_fingerprint,
        ];
    }
}
