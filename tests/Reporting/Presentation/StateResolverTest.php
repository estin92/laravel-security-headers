<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Reporting\Fields\KnownFieldCatalogue;
use Estin92\SecurityHeaders\Reporting\Presentation\ResolverCaps;
use Estin92\SecurityHeaders\Reporting\Presentation\StateResolver;
use Estin92\SecurityHeaders\Support\JsonObject;

function reportWith(array $bodyNative, array $actions = [], array $attrs = []): SecurityReport
{
    $report = new SecurityReport;
    $report->forceFill(array_merge([
        'type' => 'csp-violation',
        'protocol' => 'reporting-api',
        'url' => 'https://app.example/p',
        'url_origin' => 'https://app.example',
        'age' => 0,
        'reported_user_agent' => null,
        'request_user_agent' => 'req-UA',
        'client_ip' => null,
        'storage_mode' => 'sanitized',
        'sanitizer_version' => 'v1',
        'sanitization_actions' => $actions,
        'incident_fingerprint' => str_repeat('a', 64),
    ], $attrs));

    $report->body = JsonObject::fromNative((object) $bodyNative);

    return $report;
}

function bodyNodes(array $nodes): array
{
    foreach ($nodes as $node) {
        if ($node->key === 'body') {
            return $node->children ?? [];
        }
    }

    return [];
}

function nodeByKey(array $nodes, string $key)
{
    foreach ($nodes as $node) {
        if ($node->key === $key) {
            return $node;
        }
    }

    return null;
}

function countNodes(array $nodes): int
{
    $count = 0;

    foreach ($nodes as $node) {
        $count++;

        if (is_array($node->children)) {
            $count += countNodes($node->children);
        }
    }

    return $count;
}

function countOmitted(array $nodes): int
{
    $omitted = 0;

    foreach ($nodes as $node) {
        $omitted += $node->childrenOmitted;

        if (is_array($node->children)) {
            $omitted += countOmitted($node->children);
        }
    }

    return $omitted;
}

function resolveReport(SecurityReport $report, ?ResolverCaps $caps = null): array
{
    return (new StateResolver(new KnownFieldCatalogue))->resolve($report, $caps ?? new ResolverCaps);
}

test('a present scalar field resolves to present with its raw unescaped value', function () {
    $report = reportWith(['blockedURL' => 'https://evil/<script>']);
    $node = nodeByKey(bodyNodes(resolveReport($report)), 'blockedURL');

    expect($node->state->value)->toBe('present');
    expect($node->value)->toBe('https://evil/<script>');
    expect($node->valueType)->toBe('string');
    expect($node->path)->toBe(['body', 'blockedURL']);
});

test('an empty value resolves to empty and keeps object-vs-list identity', function () {
    $report = reportWith(['request_headers' => (object) [], 'response_headers' => []], [], ['type' => 'network-error']);
    $nodes = bodyNodes(resolveReport($report));

    expect(nodeByKey($nodes, 'request_headers')->state->value)->toBe('empty');
    expect(nodeByKey($nodes, 'request_headers')->valueType)->toBe('object');
    expect(nodeByKey($nodes, 'response_headers')->state->value)->toBe('empty');
    expect(nodeByKey($nodes, 'response_headers')->valueType)->toBe('list');
});

test('a strip_query action resolves to transformed showing the persisted value and the action', function () {
    $report = reportWith(
        ['blockedURL' => 'https://evil/x'],
        [['path' => ['body', 'blockedURL'], 'action' => 'strip_query']],
    );
    $node = nodeByKey(bodyNodes(resolveReport($report)), 'blockedURL');

    expect($node->state->value)->toBe('transformed');
    expect($node->value)->toBe('https://evil/x');
    expect($node->action)->toBe('strip_query');
});

test('a remove action resolves to removed with no value', function () {
    $report = reportWith(
        [],
        [['path' => ['body', 'sample'], 'action' => 'remove_sample']],
    );
    $node = nodeByKey(bodyNodes(resolveReport($report)), 'sample');

    expect($node->state->value)->toBe('removed');
    expect($node->value)->toBeNull();
    expect($node->action)->toBe('remove_sample');
});

test('an unrecognized action resolves to unknown_action, never transformed, with no value', function () {
    $report = reportWith(
        ['blockedURL' => 'kept?'],
        [['path' => ['body', 'blockedURL'], 'action' => 'future_scrub']],
    );
    $node = nodeByKey(bodyNodes(resolveReport($report)), 'blockedURL');

    expect($node->state->value)->toBe('unknown_action');
    expect($node->action)->toBe('future_scrub');
    expect($node->value)->toBeNull();
});

test('a catalogue field absent from the submission resolves to not_submitted in catalogue order', function () {
    $report = reportWith(['blockedURL' => 'x']);
    $nodes = bodyNodes(resolveReport($report));

    expect(nodeByKey($nodes, 'statusCode')->state->value)->toBe('not_submitted');
    expect(nodeByKey($nodes, 'disposition')->state->value)->toBe('not_submitted');

    $keys = array_map(fn ($n) => $n->key, $nodes);
    expect(array_search('documentURL', $keys, true))->toBeLessThan(array_search('blockedURL', $keys, true));
});

test('a consumer type generates no not_submitted rows, only present values and actions', function () {
    $report = reportWith(['whatever' => 'x'], [], ['type' => 'document-policy-violation']);
    $nodes = bodyNodes(resolveReport($report));

    expect(nodeByKey($nodes, 'whatever')->state->value)->toBe('present');
    expect(array_filter($nodes, fn ($n) => $n->state->value === 'not_submitted'))->toBe([]);
});

test('the promoted context fields are resolved with the same states as body fields', function () {
    $report = reportWith(
        ['blockedURL' => 'x'],
        [['path' => ['client_ip'], 'action' => 'remove_client_ip']],
        ['client_ip' => null],
    );
    $nodes = resolveReport($report);

    expect(nodeByKey($nodes, 'client_ip')->state->value)->toBe('removed');
    expect(nodeByKey($nodes, 'client_ip')->action)->toBe('remove_client_ip');
    expect(nodeByKey($nodes, 'url')->state->value)->toBe('present');
    expect(nodeByKey($nodes, 'url')->value)->toBe('https://app.example/p');
});

test('a value-length cap truncates the scalar and surfaces truncated', function () {
    $long = str_repeat('a', 10_000);
    $report = reportWith(['blockedURL' => $long]);
    $node = nodeByKey(bodyNodes(resolveReport($report, new ResolverCaps(maxValueLength: 100))), 'blockedURL');

    expect(strlen((string) $node->value))->toBe(100);
    expect($node->truncated)->toBeTrue();
});

test('the global node cap bounds total nodes even when every container is under maxChildren', function () {
    $wide = [];
    for ($i = 0; $i < 30; $i++) {
        $inner = [];
        for ($j = 0; $j < 30; $j++) {
            $inner["k{$j}"] = 'v';
        }
        $wide["g{$i}"] = (object) $inner;
    }
    $report = reportWith($wide, [], ['type' => 'document-policy-violation']);

    $nodes = resolveReport($report, new ResolverCaps(maxChildren: 50, maxNodes: 100));

    expect(countNodes(bodyNodes($nodes)))->toBeLessThanOrEqual(100);

    expect(countOmitted($nodes))->toBeGreaterThan(0);
});

test('the global node cap bounds a catalogue type and surfaces the omission on the body node', function () {
    $report = reportWith(['blockedURL' => 'x'], [], ['type' => 'network-error']);

    $nodes = resolveReport($report, new ResolverCaps(maxNodes: 3));

    expect(countNodes(bodyNodes($nodes)))->toBeLessThanOrEqual(3);

    $body = nodeByKey($nodes, 'body');
    expect($body->childrenOmitted)->toBeGreaterThan(0);
});

test('the context skeleton is always emitted in full even when the node cap is exhausted', function () {
    $report = reportWith(['blockedURL' => 'x'], [], ['type' => 'network-error']);

    $nodes = resolveReport($report, new ResolverCaps(maxNodes: 1));

    expect($nodes)->toHaveCount(5);
    expect(nodeByKey($nodes, 'url'))->not->toBeNull();
    expect(nodeByKey($nodes, 'client_ip'))->not->toBeNull();
    expect(nodeByKey($nodes, 'request_user_agent'))->not->toBeNull();
    expect(nodeByKey($nodes, 'reported_user_agent'))->not->toBeNull();
    expect(nodeByKey($nodes, 'body'))->not->toBeNull();
});

test('an empty-string context field resolves to empty, matching body-field semantics', function () {
    $report = reportWith(['blockedURL' => 'x'], [], ['client_ip' => '']);
    $node = nodeByKey(resolveReport($report), 'client_ip');

    expect($node->state->value)->toBe('empty');
});

test('a null context field resolves to not_submitted, distinct from an empty string', function () {
    $report = reportWith(['blockedURL' => 'x'], [], ['reported_user_agent' => null]);
    $node = nodeByKey(resolveReport($report), 'reported_user_agent');

    expect($node->state->value)->toBe('not_submitted');
});

test('nested object and list children are walked and carry structured paths', function () {
    $report = reportWith(
        ['request_headers' => (object) ['accept' => 'text/html', 'x' => ['a', 'b']]],
        [],
        ['type' => 'network-error'],
    );
    $headers = nodeByKey(bodyNodes(resolveReport($report)), 'request_headers');

    expect($headers->valueType)->toBe('object');
    $x = nodeByKey($headers->children, 'x');
    expect($x->valueType)->toBe('list');
    expect($x->children[0]->path)->toBe(['body', 'request_headers', 'x', 0]);
    expect($x->children[0]->value)->toBe('a');
});
