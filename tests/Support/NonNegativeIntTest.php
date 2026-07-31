<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Support\NonNegativeInt;

test('it accepts a non-negative int', function (int $value) {
    expect(NonNegativeInt::parse($value))->toBe($value);
})->with([
    'zero' => [0],
    'positive' => [42],
]);

test('it accepts a canonical non-negative digit string', function (string $value, int $expected) {
    expect(NonNegativeInt::parse($value))->toBe($expected);
})->with([
    'zero' => ['0', 0],
    'positive' => ['10886400', 10886400],
]);

test('it returns null for anything that is not a canonical non-negative int', function (mixed $value) {
    expect(NonNegativeInt::parse($value))->toBeNull();
})->with([
    'negative int' => [-1],
    'negative string' => ['-1'],
    'decimal' => ['1.5'],
    'float' => [1.0],
    'exponent' => ['1e3'],
    'padded' => [' 1 '],
    'leading zero' => ['01'],
    'non-numeric' => ['high'],
    'oversized string' => ['999999999999999999999999'],
    'boolean' => [true],
    'null' => [null],
    'array' => [[1]],
]);
