<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Http\Viewer\PageLimit;

test('a valid in-range limit is honoured', function () {
    expect(PageLimit::from('25'))->toBe(25);
    expect(PageLimit::from(10))->toBe(10);
});

test('an out-of-range, missing, or junk limit is clamped, never returned raw', function (mixed $raw, int $expected) {
    expect(PageLimit::from($raw))->toBe($expected);
})->with([
    'null → default' => [null, 50],
    'empty string → default' => ['', 50],
    'zero → default' => ['0', 50],
    'negative → default' => ['-5', 50],
    'non-numeric → default' => ['lots', 50],
    'array → default' => [['1'], 50],
    'float → default' => [1.9, 50],
    'over max → max' => ['1000000', 100],
    'just over max → max' => ['101', 100],
    'at max → max' => ['100', 100],
    'at min → min' => ['1', 1],
]);
