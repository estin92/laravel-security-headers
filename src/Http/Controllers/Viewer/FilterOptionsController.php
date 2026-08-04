<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Controllers\Viewer;

use Estin92\SecurityHeaders\Models\SecurityReport;
use Illuminate\Http\JsonResponse;

final class FilterOptionsController
{
    private const URL_ORIGIN_CAP = 100;

    public function __invoke(): JsonResponse
    {
        $origins = SecurityReport::query()
            ->select('url_origin')
            ->whereNotNull('url_origin')
            ->distinct()
            ->orderBy('url_origin')
            ->limit(self::URL_ORIGIN_CAP + 1)
            ->pluck('url_origin')
            ->all();

        $truncated = count($origins) > self::URL_ORIGIN_CAP;

        return new JsonResponse([
            'type' => $this->distinct('type'),
            'protocol' => $this->distinct('protocol'),
            'url_origin' => array_slice($origins, 0, self::URL_ORIGIN_CAP),
            'url_origin_truncated' => $truncated,
        ]);
    }

    /**
     * @return list<string>
     */
    private function distinct(string $column): array
    {
        $values = SecurityReport::query()
            ->select($column)
            ->distinct()
            ->orderBy($column)
            ->pluck($column)
            ->all();

        return array_values(array_filter($values, 'is_string'));
    }
}
