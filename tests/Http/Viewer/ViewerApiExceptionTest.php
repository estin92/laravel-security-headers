<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Http\Viewer\ViewerApiException;
use Illuminate\Http\Request;

test('each named constructor carries its stable code and status without shadowing Exception', function () {
    $cases = [
        ['forbidden', 'forbidden', 403],
        ['invalidFilter', 'invalid_filter', 422],
        ['invalidFingerprint', 'invalid_fingerprint', 422],
        ['invalidCursor', 'invalid_cursor', 422],
        ['notFound', 'not_found', 404],
    ];

    foreach ($cases as [$ctor, $code, $status]) {
        $exception = ViewerApiException::{$ctor}();

        expect($exception->errorCode)->toBe($code);
        expect($exception->httpStatus)->toBe($status);
        expect($exception->getMessage())->toBeString()->not->toBe('');
    }
});

test('it self-renders the fixed JSON envelope and leaks no stored content', function () {
    $response = ViewerApiException::notFound()->toResponse(Request::create('/x'));

    expect($response->getStatusCode())->toBe(404);
    expect($response->getData(true))->toBe([
        'error' => 'not_found',
        'message' => ViewerApiException::notFound()->getMessage(),
    ]);
});
