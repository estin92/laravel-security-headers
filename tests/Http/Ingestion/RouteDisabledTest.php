<?php

declare(strict_types=1);

test('the ingestion route is absent when ingestion is disabled', function (string $method) {
    $response = test()->call($method, '/security/reports', [], [], [], ['CONTENT_TYPE' => 'application/reports+json'], '[]');

    $response->assertNotFound();
})->with(['POST', 'OPTIONS']);
