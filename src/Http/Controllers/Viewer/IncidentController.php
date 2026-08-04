<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Controllers\Viewer;

use Estin92\SecurityHeaders\Http\Viewer\CursorCodec;
use Estin92\SecurityHeaders\Http\Viewer\PageLimit;
use Estin92\SecurityHeaders\Http\Viewer\ViewerApiException;
use Estin92\SecurityHeaders\Models\SecurityReport;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class IncidentController
{
    public function __invoke(Request $request, string $fingerprint): JsonResponse
    {
        if (preg_match('/^[0-9a-f]{64}$/', $fingerprint) !== 1) {
            throw ViewerApiException::invalidFingerprint();
        }

        $query = SecurityReport::query()
            ->where('incident_fingerprint', $fingerprint)
            ->orderByDesc('received_at')
            ->orderByDesc('id');

        $page = CursorCodec::paginate($query, PageLimit::from($request->query('limit')), $request->query('cursor'));

        return new JsonResponse([
            'data' => $page->items->map(fn (SecurityReport $report): array => [
                'id' => $report->id,
                'type' => $report->type,
                'received_at' => $report->received_at->toIso8601ZuluString(),
            ]),
            'next_cursor' => $page->nextCursor,
        ]);
    }
}
