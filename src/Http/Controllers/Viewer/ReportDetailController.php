<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Controllers\Viewer;

use Estin92\SecurityHeaders\Http\Viewer\ReportDetailPresenter;
use Estin92\SecurityHeaders\Http\Viewer\ViewerApiException;
use Estin92\SecurityHeaders\Models\SecurityReport;
use Illuminate\Http\JsonResponse;

final class ReportDetailController
{
    public function __construct(private readonly ReportDetailPresenter $presenter) {}

    public function __invoke(int $id): JsonResponse
    {
        $report = SecurityReport::query()->find($id);

        if ($report === null) {
            throw ViewerApiException::notFound();
        }

        return new JsonResponse(['data' => $this->presenter->present($report)]);
    }
}
