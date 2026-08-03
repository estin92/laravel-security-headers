<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Models\Casts\JsonObjectCast;
use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Support\JsonObject;
use Illuminate\Support\Facades\Log;

function cast(): JsonObjectCast
{
    return new JsonObjectCast;
}

test('get returns null for a stored value that is not a JSON object', function (string $stored) {
    expect(cast()->get(new SecurityReport, 'body', $stored, []))->toBeNull();
})->with([
    'a list' => ['[1,2,3]'],
    'a number' => ['5'],
    'a string' => ['"hello"'],
]);

test('get returns null when the stored value is null', function () {
    expect(cast()->get(new SecurityReport, 'body', null, []))->toBeNull();
});

test('get decodes a stored object into a JsonObject', function () {
    $result = cast()->get(new SecurityReport, 'body', '{"a":1}', []);

    expect($result)->toBeInstanceOf(JsonObject::class);
    expect($result->get(['a']))->toBe(1);
});

test('get returns null and logs when the stored body is corrupt', function () {
    Log::shouldReceive('error')->once();

    expect(cast()->get(new SecurityReport, 'body', '{"a":', []))->toBeNull();
});

test('set serialises a JsonObject to its JSON string', function () {
    $body = JsonObject::fromNative(json_decode('{"a":1}', false));

    expect(cast()->set(new SecurityReport, 'body', $body, []))->toBe('{"a":1}');
});

test('set returns null for a null body', function () {
    expect(cast()->set(new SecurityReport, 'body', null, []))->toBeNull();
});

test('set rejects a value that is not a JsonObject', function () {
    expect(fn () => cast()->set(new SecurityReport, 'body', ['not' => 'a json object'], []))
        ->toThrow(InvalidArgumentException::class);
});
