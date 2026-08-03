<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;

test('every rejection reason maps to the specified HTTP status', function (string $reason, int $status) {
    expect(RejectionReason::from($reason)->status())->toBe($status);
})->with([
    ['unsupported_media_type', 415],
    ['malformed_json', 400],
    ['invalid_envelope', 400],
    ['request_too_large', 413],
    ['batch_too_large', 413],
    ['unaccepted_report_type', 422],
    ['invalid_report_body', 422],
    ['invalid_field', 422],
    ['origin_not_allowed', 403],
    ['rate_limited', 429],
]);

test('a rejection reason never means the service itself was unavailable', function () {
    expect(RejectionReason::tryFrom('service_unavailable'))->toBeNull();
});

test('every rejection reason has a client-error or larger status', function () {
    foreach (RejectionReason::cases() as $reason) {
        expect($reason->status())->toBeGreaterThanOrEqual(400);
    }
});
