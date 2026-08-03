<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidReportSubmission;
use Estin92\SecurityHeaders\Reporting\Ingestion\ModernReportDecoder;
use Estin92\SecurityHeaders\Reporting\Ingestion\NormalizedReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeResolver;
use Estin92\SecurityHeaders\Support\JsonObject;

function modernDecoder(array $overrides = []): ModernReportDecoder
{
    $limits = array_merge([
        'max_bytes' => 65536,
        'max_reports_per_batch' => 100,
        'json_depth' => 32,
        'url_length' => 8192,
        'user_agent_length' => 1024,
    ], $overrides);

    return new ModernReportDecoder(ReportTypeResolver::forEnum(ReportType::class), $limits);
}

function modernEntry(array $overrides = []): array
{
    return array_merge([
        'type' => 'csp-violation',
        'age' => 10,
        'url' => 'https://example.com/page',
        'user_agent' => 'Mozilla/5.0',
        'body' => ['blockedURL' => 'https://evil.example/x'],
    ], $overrides);
}

function decodeReason(callable $fn): RejectionReason
{
    try {
        $fn();
    } catch (InvalidReportSubmission $e) {
        return $e->reason;
    }

    throw new RuntimeException('Expected InvalidReportSubmission, none thrown.');
}

test('a one-report batch decodes to one normalized report', function () {
    $reports = modernDecoder()->decode(json_encode([modernEntry()]));

    expect($reports)->toHaveCount(1);
    expect($reports[0])->toBeInstanceOf(NormalizedReport::class);
    expect($reports[0]->type)->toBe(ReportType::CspViolation);
    expect($reports[0]->url)->toBe('https://example.com/page');
    expect($reports[0]->age)->toBe(10);
    expect($reports[0]->reportedUserAgent)->toBe('Mozilla/5.0');
    expect($reports[0]->protocol)->toBe(ReportProtocol::ReportingApi);
});

test('an empty object body stays an object, not a list', function () {
    $raw = '[{"type":"csp-violation","age":0,"url":"https://x","user_agent":"UA","body":{}}]';
    $reports = modernDecoder()->decode($raw);

    expect($reports[0]->body)->toBeInstanceOf(JsonObject::class);
    expect($reports[0]->body->toJson())->toBe('{}');
});

test('a null body is carried through as null', function () {
    $reports = modernDecoder()->decode(json_encode([modernEntry(['body' => null])]));

    expect($reports[0]->body)->toBeNull();
});

test('an empty batch decodes to nothing without throwing', function () {
    expect(modernDecoder()->decode('[]'))->toBe([]);
});

test('unknown envelope members are ignored', function () {
    $reports = modernDecoder()->decode(json_encode([modernEntry(['destination' => 'group-a'])]));

    expect($reports)->toHaveCount(1);
});

test('a non-list top level is a malformed envelope', function () {
    expect(decodeReason(fn () => modernDecoder()->decode('{"type":"csp-violation"}')))
        ->toBe(RejectionReason::InvalidEnvelope);
});

test('a report missing any of the five members is a malformed envelope', function (string $member) {
    $entry = modernEntry();
    unset($entry[$member]);

    expect(decodeReason(fn () => modernDecoder()->decode(json_encode([$entry]))))
        ->toBe(RejectionReason::InvalidEnvelope);
})->with(['type', 'age', 'url', 'user_agent', 'body']);

test('an age that is not a genuine non-negative integer is a malformed envelope', function (mixed $age) {
    expect(decodeReason(fn () => modernDecoder()->decode(json_encode([modernEntry(['age' => $age])]))))
        ->toBe(RejectionReason::InvalidEnvelope);
})->with([
    'float' => [1.5],
    'numeric string' => ['10'],
    'boolean' => [true],
    'negative' => [-1],
]);

test('a non-string type, url or user_agent is a malformed envelope', function (string $member) {
    expect(decodeReason(fn () => modernDecoder()->decode(json_encode([modernEntry([$member => 123])]))))
        ->toBe(RejectionReason::InvalidEnvelope);
})->with(['type', 'url', 'user_agent']);

test('a body that is a list or a plain value is a malformed envelope', function (mixed $body) {
    expect(decodeReason(fn () => modernDecoder()->decode(json_encode([modernEntry(['body' => $body])]))))
        ->toBe(RejectionReason::InvalidEnvelope);
})->with([
    'list' => [[1, 2, 3]],
    'string' => ['a string'],
    'number' => [5],
]);

test('a type with bad grammar is an invalid field, not a malformed envelope', function () {
    expect(decodeReason(fn () => modernDecoder()->decode(json_encode([modernEntry(['type' => 'CSP_Violation'])]))))
        ->toBe(RejectionReason::InvalidField);
});

test('an over-length url or user_agent is an invalid field', function (string $member, int $limitKey) {
    $long = str_repeat('a', $limitKey + 1);

    expect(decodeReason(fn () => modernDecoder()->decode(json_encode([modernEntry([$member => $long])]))))
        ->toBe(RejectionReason::InvalidField);
})->with([
    'url' => ['url', 8192],
    'user_agent' => ['user_agent', 1024],
]);

test('a type the configured enum does not accept is rejected for the whole batch', function () {
    $batch = [modernEntry(), modernEntry(['type' => 'unheard-of'])];

    expect(decodeReason(fn () => modernDecoder()->decode(json_encode($batch))))
        ->toBe(RejectionReason::UnacceptedReportType);
});

test('a body too large before decode is rejected', function () {
    $raw = json_encode([modernEntry()]);

    expect(decodeReason(fn () => modernDecoder(['max_bytes' => 10])->decode($raw)))
        ->toBe(RejectionReason::RequestTooLarge);
});

test('a batch with too many reports is rejected', function () {
    $batch = array_fill(0, 3, modernEntry());

    expect(decodeReason(fn () => modernDecoder(['max_reports_per_batch' => 2])->decode(json_encode($batch))))
        ->toBe(RejectionReason::BatchTooLarge);
});

test('json nested past the depth limit is malformed json', function () {
    $raw = json_encode([modernEntry(['body' => ['a' => ['b' => ['c' => 1]]]])]);

    expect(decodeReason(fn () => modernDecoder(['json_depth' => 3])->decode($raw)))
        ->toBe(RejectionReason::MalformedJson);
});

test('syntactically broken json is malformed json', function () {
    expect(decodeReason(fn () => modernDecoder()->decode('[{"type":')))
        ->toBe(RejectionReason::MalformedJson);
});
