<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Ingestion;

use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use Illuminate\Http\JsonResponse;

class ErrorResponse
{
    /**
     * @param  array<string, string>  $headers
     */
    public static function for(RejectionReason $reason, array $headers = []): JsonResponse
    {
        return self::json($reason->value, $reason->status(), $headers);
    }

    public static function serviceUnavailable(): JsonResponse
    {
        return self::json('service_unavailable', 503);
    }

    public static function code(string $code, int $status): JsonResponse
    {
        return self::json($code, $status);
    }

    /**
     * @param  array<string, string>  $headers
     */
    private static function json(string $code, int $status, array $headers = []): JsonResponse
    {
        return new JsonResponse(['error' => $code], $status, $headers);
    }
}
