<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Viewer;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use RuntimeException;

final class ViewerApiException extends RuntimeException implements Responsable
{
    public function __construct(
        public readonly string $errorCode,
        public readonly int $httpStatus,
        string $message,
    ) {
        parent::__construct($message);
    }

    public static function forbidden(): self
    {
        return new self('forbidden', 403, 'You are not authorized to view security header reports.');
    }

    public static function invalidFilter(): self
    {
        return new self('invalid_filter', 422, 'One or more filters were not recognized or were malformed.');
    }

    public static function invalidFingerprint(): self
    {
        return new self('invalid_fingerprint', 422, 'The incident fingerprint is not a valid 64-character hex string.');
    }

    public static function invalidCursor(): self
    {
        return new self('invalid_cursor', 422, 'The pagination cursor is malformed.');
    }

    public static function notFound(): self
    {
        return new self('not_found', 404, 'The requested report is no longer available.');
    }

    public function toResponse($request): JsonResponse
    {
        return new JsonResponse(
            ['error' => $this->errorCode, 'message' => $this->getMessage()],
            $this->httpStatus,
        );
    }
}
