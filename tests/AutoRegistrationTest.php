<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;

test('auto-registration applies headers to a plain route', function () {
    Route::get('/plain', fn () => 'ok');

    $this->get('/plain')->assertHeader('X-Frame-Options', 'DENY');
});
