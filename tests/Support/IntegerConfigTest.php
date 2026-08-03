<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Support\IntegerConfig;

test('it passes a native integer through unchanged', function () {
    expect(IntegerConfig::parse(65536))->toBe(65536);
});

test('it converts a canonical positive digit string to an integer', function () {
    expect(IntegerConfig::parse('65536'))->toBe(65536);
});

test('it leaves values that are not canonical integers untouched so the validator can reject them', function (mixed $value) {
    expect(IntegerConfig::parse($value))->toBe($value);
})->with([
    'decimal' => ['1.5'],
    'scientific' => ['1e3'],
    'surrounding whitespace' => [' 10 '],
    'leading zero' => ['01'],
    'non-numeric' => ['abc'],
    'empty' => [''],
    'negative' => ['-5'],
    'zero' => ['0'],
    'float' => [1.5],
    'true' => [true],
    'false' => [false],
    'null' => [null],
    'overflow' => ['99999999999999999999'],
]);
