<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Viewer;

use Estin92\SecurityHeaders\Models\SecurityReport;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Throwable;

final class ReportFilters
{
    private const MAX_VALUE_LENGTH = 191;

    private const EXACT = ['type', 'protocol', 'url_origin'];

    /**
     * @param  Builder<SecurityReport>  $query
     * @param  array<array-key, mixed>  $params
     * @return Builder<SecurityReport>
     */
    public function applyTo(Builder $query, array $params): Builder
    {
        foreach ($params as $key => $value) {
            if (in_array($key, self::EXACT, true)) {
                $query->where($key, $this->exactValue($value));

                continue;
            }

            if ($key === 'received_from') {
                $query->where('received_at', '>=', $this->dateValue($value));

                continue;
            }

            if ($key === 'received_to') {
                $query->where('received_at', '<', $this->dateValue($value));

                continue;
            }

            throw ViewerApiException::invalidFilter();
        }

        return $query;
    }

    private function exactValue(mixed $value): string
    {
        if (! is_string($value) || strlen($value) > self::MAX_VALUE_LENGTH) {
            throw ViewerApiException::invalidFilter();
        }

        return $value;
    }

    private function dateValue(mixed $value): Carbon
    {
        if (! is_string($value)) {
            throw ViewerApiException::invalidFilter();
        }

        try {
            return Carbon::parse($value)->utc();
        } catch (Throwable) {
            throw ViewerApiException::invalidFilter();
        }
    }
}
