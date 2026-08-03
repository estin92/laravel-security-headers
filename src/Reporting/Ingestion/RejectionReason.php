<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

// No service_unavailable case because that is the server failing not a bad report.
enum RejectionReason: string
{
    case UnsupportedMediaType = 'unsupported_media_type';
    case MalformedJson = 'malformed_json';
    case InvalidEnvelope = 'invalid_envelope';
    case RequestTooLarge = 'request_too_large';
    case BatchTooLarge = 'batch_too_large';
    case UnacceptedReportType = 'unaccepted_report_type';
    case InvalidReportBody = 'invalid_report_body';
    case InvalidField = 'invalid_field';
    case OriginNotAllowed = 'origin_not_allowed';
    case RateLimited = 'rate_limited';

    public function status(): int
    {
        return match ($this) {
            self::UnsupportedMediaType => 415,
            self::MalformedJson, self::InvalidEnvelope => 400,
            self::RequestTooLarge, self::BatchTooLarge => 413,
            self::UnacceptedReportType, self::InvalidReportBody, self::InvalidField => 422,
            self::OriginNotAllowed => 403,
            self::RateLimited => 429,
        };
    }
}
