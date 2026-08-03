<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\Ingestion\IncidentFingerprint;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Reporting\Ingestion\StorageMode;
use Estin92\SecurityHeaders\Support\JsonObject;

function fingerprintOf(
    ?JsonObject $body,
    ?string $url = 'https://example.com/p',
    ReportType $type = ReportType::CspViolation,
): string {
    return IncidentFingerprint::for(
        $type,
        ReportProtocol::ReportingApi,
        $url,
        $body,
        StorageMode::Sanitized,
        '1:'.str_repeat('a', 64),
    );
}

test('it produces a lowercase 64-character hex string', function () {
    $fingerprint = fingerprintOf(JsonObject::fromNative(json_decode('{"a":1}', false)));

    expect($fingerprint)->toMatch('/\A[0-9a-f]{64}\z/');
});

test('objects with keys in a different order hash the same', function () {
    $a = fingerprintOf(JsonObject::fromNative(json_decode('{"a":1,"b":2}', false)));
    $b = fingerprintOf(JsonObject::fromNative(json_decode('{"b":2,"a":1}', false)));

    expect($a)->toBe($b);
});

test('lists in a different order hash differently', function () {
    $a = fingerprintOf(JsonObject::fromNative(json_decode('{"l":[1,2]}', false)));
    $b = fingerprintOf(JsonObject::fromNative(json_decode('{"l":[2,1]}', false)));

    expect($a)->not->toBe($b);
});

test('an empty object and an empty list hash differently', function () {
    $object = fingerprintOf(JsonObject::fromNative(json_decode('{"v":{}}', false)));
    $list = fingerprintOf(JsonObject::fromNative(json_decode('{"v":[]}', false)));

    expect($object)->not->toBe($list);
});

test('a null body and an empty object body hash differently', function () {
    $null = fingerprintOf(null);
    $empty = fingerprintOf(JsonObject::fromNative(json_decode('{}', false)));

    expect($null)->not->toBe($empty);
});

test('the same content always hashes to the same value', function () {
    $a = fingerprintOf(JsonObject::fromNative(json_decode('{"a":{"b":[1,2,3]}}', false)));
    $b = fingerprintOf(JsonObject::fromNative(json_decode('{"a":{"b":[1,2,3]}}', false)));

    expect($a)->toBe($b);
});

test('type, protocol and url each change the fingerprint', function () {
    $base = fingerprintOf(null);

    $differentType = IncidentFingerprint::for(ReportType::Coop, ReportProtocol::ReportingApi, 'https://example.com/p', null, StorageMode::Sanitized, '1:'.str_repeat('a', 64));
    $differentProtocol = IncidentFingerprint::for(ReportType::CspViolation, ReportProtocol::LegacyCspReportUri, 'https://example.com/p', null, StorageMode::Sanitized, '1:'.str_repeat('a', 64));
    $differentUrl = fingerprintOf(null, 'https://example.com/other');

    expect($differentType)->not->toBe($base);
    expect($differentProtocol)->not->toBe($base);
    expect($differentUrl)->not->toBe($base);
});
