<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Http\Viewer\CursorCodec;
use Estin92\SecurityHeaders\Http\Viewer\ViewerApiException;
use Illuminate\Support\Carbon;

test('a cursor round-trips its received_at and id', function () {
    $at = Carbon::parse('2026-08-01T12:34:56Z');
    $decoded = CursorCodec::decode(CursorCodec::encode($at, 42));

    expect($decoded['id'])->toBe(42);
    expect($decoded['received_at']->equalTo($at))->toBeTrue();
});

test('the encoded cursor is opaque — it leaks no plaintext id or timestamp', function () {
    $token = CursorCodec::encode(Carbon::parse('2026-08-01T12:34:56Z'), 42);

    expect($token)->not->toContain('42');
    expect($token)->not->toContain('2026');
});

test('every malformed cursor is rejected as invalid_cursor, never fatalled or silently accepted', function (string $bad) {
    try {
        CursorCodec::decode($bad);
        $this->fail('expected ViewerApiException');
    } catch (ViewerApiException $exception) {
        expect($exception->errorCode)->toBe('invalid_cursor');
        expect($exception->httpStatus)->toBe(422);
    }
})->with([
    'empty' => [''],
    'not base64' => ['!!!!'],
    'truncated base64' => ['YWJj'],
    'valid base64 wrong json' => [base64_encode('{"nope":1}')],
    'valid json wrong types' => [base64_encode('{"received_at":"x","id":"nope"}')],
    'array not object' => [base64_encode('[1,2]')],
    'negative id' => [base64_encode('{"received_at":"2026-08-01T00:00:00Z","id":-5}')],
]);
