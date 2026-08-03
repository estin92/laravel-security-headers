<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\MissingJsonPath;
use Estin92\SecurityHeaders\Support\JsonObject;

function jsonObject(string $json): JsonObject
{
    return JsonObject::fromNative(json_decode($json, false, 512, JSON_THROW_ON_ERROR));
}

test('reads a nested value by path', function () {
    $o = jsonObject('{"body":{"blockedURL":"https://x/y"}}');

    expect($o->get(['body', 'blockedURL']))->toBe('https://x/y');
});

test('returns a nested object as another JsonObject', function () {
    $o = jsonObject('{"body":{"n":1}}');

    expect($o->get(['body']))->toBeInstanceOf(JsonObject::class);
});

test('addresses a list element by its integer index', function () {
    $o = jsonObject('{"frames":[{"url":"a"},{"url":"b"}]}');

    expect($o->get(['frames', 1, 'url']))->toBe('b');
});

test('a key holding null is present, a missing key is not', function () {
    $o = jsonObject('{"a":null}');

    expect($o->has(['a']))->toBeTrue();
    expect($o->has(['missing']))->toBeFalse();
    expect($o->get(['a']))->toBeNull();
});

test('get throws when the path is missing', function () {
    $o = jsonObject('{"a":1}');

    expect(fn () => $o->get(['b']))->toThrow(MissingJsonPath::class);
});

test('getOrNull returns null when the path is missing', function () {
    $o = jsonObject('{"a":1}');

    expect($o->getOrNull(['b']))->toBeNull();
});

test('getOrNull returns the value when the path is present', function () {
    $o = jsonObject('{"a":{"b":1}}');

    expect($o->getOrNull(['a', 'b']))->toBe(1);
});

test('a list index past the end is missing', function () {
    $o = jsonObject('{"frames":[{"url":"a"}]}');

    expect($o->has(['frames', 5]))->toBeFalse();
    expect($o->getOrNull(['frames', 5]))->toBeNull();
    expect(fn () => $o->get(['frames', 5]))->toThrow(MissingJsonPath::class);
});

test('a string index into a list, or an integer key into an object, is missing', function () {
    $o = jsonObject('{"obj":{"k":1},"list":[10]}');

    expect($o->has(['obj', 0]))->toBeFalse();
    expect($o->has(['list', 'k']))->toBeFalse();
    expect($o->has(['obj', 'k', 'deeper']))->toBeFalse();
});

test('a list handed to the caller cannot be written back into the object', function () {
    $o = jsonObject('{"frames":[{"url":"a"},{"url":"b"}]}');
    $frames = $o->get(['frames']);

    expect($frames)->toBeArray();
    $frames[0]->url = 'mutated';

    expect($o->get(['frames', 0, 'url']))->toBe('a');
});

test('a nested object handed to the caller shares no data with its parent', function () {
    $o = jsonObject('{"a":{"b":1}}');
    $nested = $o->get(['a']);
    $nested->toNative()->b = 999;

    expect($o->get(['a', 'b']))->toBe(1);
});

test('toNative gives back a copy that cannot be written into the object', function () {
    $o = jsonObject('{"a":{"b":1},"frames":[{"url":"a"}]}');
    $native = $o->toNative();
    $native->a->b = 999;
    $native->frames[0]->url = 'mutated';

    expect($o->get(['a', 'b']))->toBe(1);
    expect($o->get(['frames', 0, 'url']))->toBe('a');
});

test('toJson keeps objects and lists distinct', function () {
    expect(jsonObject('{}')->toJson())->toBe('{}');
    expect(jsonObject('{"x":[]}')->toJson())->toBe('{"x":[]}');
    expect(jsonObject('{"0":"a"}')->toJson())->toBe('{"0":"a"}');
});

test('fromNative rejects anything that is not an object', function () {
    expect(fn () => JsonObject::fromNative([]))->toThrow(TypeError::class);
});

test('changing the decoded input after construction cannot reach inside the object', function () {
    $raw = json_decode('{"a":{"b":1},"list":[{"x":1}]}', false, 512, JSON_THROW_ON_ERROR);
    $o = JsonObject::fromNative($raw);

    $raw->a->b = 999;
    $raw->list[0]->x = 999;

    expect($o->get(['a', 'b']))->toBe(1);
    expect($o->get(['list', 0, 'x']))->toBe(1);
});

test('a stored value never trips the internal missing-key check', function () {
    $decoy = "\0__absent__\0";
    $o = jsonObject(json_encode(['a' => $decoy], JSON_THROW_ON_ERROR));

    expect($o->has(['a']))->toBeTrue();
    expect($o->get(['a']))->toBe($decoy);
    expect($o->getOrNull(['a']))->toBe($decoy);
});
