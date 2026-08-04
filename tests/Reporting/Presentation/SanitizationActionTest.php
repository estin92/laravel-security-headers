<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\Presentation\FieldState;
use Estin92\SecurityHeaders\Reporting\Presentation\SanitizationAction;

test('transforming actions classify as transformed', function (string $action) {
    expect(SanitizationAction::classify($action))->toBe(FieldState::Transformed);
})->with(['strip_query', 'mask_client_ip']);

test('removing actions classify as removed', function (string $action) {
    expect(SanitizationAction::classify($action))->toBe(FieldState::Removed);
})->with([
    'remove_client_ip', 'remove_sample', 'remove_nel_headers',
    'remove_request_user_agent', 'remove_reported_user_agent',
]);

test('an unrecognized action classifies as unknown_action, never guessed', function (string $action) {
    expect(SanitizationAction::classify($action))->toBe(FieldState::UnknownAction);
})->with([
    'unprefixed future action' => ['future_scrub_v2'],
    'differently-worded' => ['redact_everything'],
    'unknown remove_-prefixed action' => ['remove_future_field'],
    'unknown mask-like action' => ['mask_something_new'],
]);
