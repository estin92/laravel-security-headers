<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use Estin92\SecurityHeaders\Exceptions\InvalidReportSubmission;
use Estin92\SecurityHeaders\Support\JsonObject;
use JsonException;
use stdClass;

final class LegacyCspReportDecoder
{
    private const KEY_MAP = [
        'document-uri' => 'documentURL',
        'blocked-uri' => 'blockedURL',
        'effective-directive' => 'effectiveDirective',
        'violated-directive' => 'effectiveDirective',
        'original-policy' => 'originalPolicy',
        'source-file' => 'sourceFile',
        'script-sample' => 'sample',
        'status-code' => 'statusCode',
        'line-number' => 'lineNumber',
        'column-number' => 'columnNumber',
    ];

    /**
     * @param  array{max_bytes: int, json_depth: positive-int}  $limits
     */
    public function __construct(
        private readonly ReportTypeResolver $resolver,
        private readonly array $limits,
    ) {}

    /**
     * @throws InvalidReportSubmission
     */
    public function decode(string $raw): NormalizedReport
    {
        if (strlen($raw) > $this->limits['max_bytes']) {
            throw InvalidReportSubmission::because(RejectionReason::RequestTooLarge);
        }

        $report = $this->unwrap($this->parse($raw));
        $body = $this->normalize($report);

        return new NormalizedReport(
            $this->resolver->resolve(ReportType::CspViolation->value),
            null,
            null,
            null,
            JsonObject::fromNative($body),
            ReportProtocol::LegacyCspReportUri,
        );
    }

    private function parse(string $raw): mixed
    {
        try {
            return json_decode($raw, false, $this->limits['json_depth'], JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw InvalidReportSubmission::because(RejectionReason::MalformedJson);
        }
    }

    private function unwrap(mixed $decoded): stdClass
    {
        if (! $decoded instanceof stdClass || ! property_exists($decoded, 'csp-report')) {
            throw InvalidReportSubmission::because(RejectionReason::InvalidEnvelope);
        }

        $report = $decoded->{'csp-report'};

        if (! $report instanceof stdClass) {
            throw InvalidReportSubmission::because(RejectionReason::InvalidEnvelope);
        }

        return $report;
    }

    private function normalize(stdClass $report): stdClass
    {
        $body = new stdClass;

        foreach (get_object_vars($report) as $key => $value) {
            $canonical = self::KEY_MAP[$key] ?? $key;

            if (property_exists($body, $canonical) && $body->{$canonical} !== $value) {
                throw InvalidReportSubmission::because(RejectionReason::InvalidField);
            }

            $body->{$canonical} = $value;
        }

        return $body;
    }
}
