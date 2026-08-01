<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Support\Fraction;

test('it accepts a native float in range', function (float $value) {
    expect(Fraction::parse($value))->toBe($value);
})->with([
    'zero' => [0.0],
    'half' => [0.5],
    'one' => [1.0],
    'quarter' => [0.25],
]);

test('it accepts a native int at the bounds', function (int $value, float $expected) {
    expect(Fraction::parse($value))->toBe($expected);
})->with([
    'zero' => [0, 0.0],
    'one' => [1, 1.0],
]);

test('it accepts a restricted-decimal string', function (string $value, float $expected) {
    expect(Fraction::parse($value))->toBe($expected);
})->with([
    'zero' => ['0', 0.0],
    'one' => ['1', 1.0],
    'half' => ['0.5', 0.5],
    'trailing zeros' => ['0.50', 0.5],
    'one point zero' => ['1.0', 1.0],
    'one point zeros' => ['1.00', 1.0],
]);

test('it returns null for anything that is not a valid fraction', function (mixed $value) {
    expect(Fraction::parse($value))->toBeNull();
})->with([
    'above one int' => [2],
    'above one float' => [1.5],
    'below zero float' => [-0.1],
    'above one string' => ['1.5'],
    'below zero string' => ['-0.1'],
    'no leading digit' => ['.5'],
    'leading zero int-part' => ['00'],
    'leading zero padded' => ['015'],
    'exponent' => ['5e-1'],
    'padded' => [' 0.5 '],
    'plus sign' => ['+0.5'],
    'minus zero' => ['-0'],
    'non-numeric' => ['abc'],
    'empty' => [''],
    'infinity' => [INF],
    'nan' => [NAN],
    'boolean true' => [true],
    'boolean false' => [false],
    'null' => [null],
    'array' => [[0.5]],
]);
