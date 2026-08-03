<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use Estin92\SecurityHeaders\Exceptions\InvalidReportSubmission;
use Estin92\SecurityHeaders\Support\JsonObject;
use JsonException;
use stdClass;

final class ModernReportDecoder
{
    /**
     * @param  array{max_bytes: int, max_reports_per_batch: int, json_depth: positive-int, url_length: int, user_agent_length: int}  $limits
     */
    public function __construct(
        private readonly ReportTypeResolver $resolver,
        private readonly array $limits,
    ) {}

    /**
     * @return list<NormalizedReport>
     *
     * @throws InvalidReportSubmission
     */
    public function decode(string $raw): array
    {
        if (strlen($raw) > $this->limits['max_bytes']) {
            throw InvalidReportSubmission::because(RejectionReason::RequestTooLarge);
        }

        // A batch is a JSON list, decode it to an array here.
        $batch = $this->parse($raw);

        if (! is_array($batch)) {
            throw InvalidReportSubmission::because(RejectionReason::InvalidEnvelope);
        }

        if (count($batch) > $this->limits['max_reports_per_batch']) {
            throw InvalidReportSubmission::because(RejectionReason::BatchTooLarge);
        }

        return array_values(array_map(fn (mixed $entry): NormalizedReport => $this->decodeEntry($entry), $batch));
    }

    private function parse(string $raw): mixed
    {
        try {
            return json_decode($raw, false, $this->limits['json_depth'], JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw InvalidReportSubmission::because(RejectionReason::MalformedJson);
        }
    }

    private function decodeEntry(mixed $entry): NormalizedReport
    {
        if (! $entry instanceof stdClass || ! $this->hasAllMembers($entry)) {
            throw InvalidReportSubmission::because(RejectionReason::InvalidEnvelope);
        }

        $type = $this->readType($entry->type);
        $age = $this->readAge($entry->age);
        $url = $this->readBoundedString($entry->url, $this->limits['url_length']);
        $userAgent = $this->readBoundedString($entry->user_agent, $this->limits['user_agent_length']);
        $body = $this->readBody($entry->body);

        return new NormalizedReport(
            $this->resolver->resolve($type),
            $url,
            $age,
            $userAgent,
            $body,
            ReportProtocol::ReportingApi,
        );
    }

    private function hasAllMembers(stdClass $entry): bool
    {
        foreach (['type', 'age', 'url', 'user_agent', 'body'] as $member) {
            if (! property_exists($entry, $member)) {
                return false;
            }
        }

        return true;
    }

    private function readType(mixed $type): string
    {
        if (! is_string($type)) {
            throw InvalidReportSubmission::because(RejectionReason::InvalidEnvelope);
        }

        // It's a string, just not one we allow, so it's a 422 rather than a 400.
        if (strlen($type) > 64 || preg_match('/\A[a-z][a-z0-9-]*\z/', $type) !== 1) {
            throw InvalidReportSubmission::because(RejectionReason::InvalidField);
        }

        return $type;
    }

    private function readAge(mixed $age): int
    {
        // Must be a real integer. "10", 1.5 and true are all rejected here.
        if (! is_int($age) || $age < 0) {
            throw InvalidReportSubmission::because(RejectionReason::InvalidEnvelope);
        }

        return $age;
    }

    private function readBoundedString(mixed $value, int $limit): string
    {
        if (! is_string($value)) {
            throw InvalidReportSubmission::because(RejectionReason::InvalidEnvelope);
        }

        if (strlen($value) > $limit) {
            throw InvalidReportSubmission::because(RejectionReason::InvalidField);
        }

        return $value;
    }

    private function readBody(mixed $body): ?JsonObject
    {
        if ($body === null) {
            return null;
        }

        if (! $body instanceof stdClass) {
            throw InvalidReportSubmission::because(RejectionReason::InvalidEnvelope);
        }

        return JsonObject::fromNative($body);
    }
}
