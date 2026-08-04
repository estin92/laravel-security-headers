<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\Fields\FieldKind;
use Estin92\SecurityHeaders\Reporting\Fields\KnownFieldCatalogue;

test('the csp catalogue lists every csp field in submission order with its kind', function () {
    $specs = (new KnownFieldCatalogue)->for('csp-violation');

    expect($specs)->not->toBeNull();

    $byName = collect($specs)->keyBy(fn ($s) => $s->name);

    expect($byName->get('blockedURL')->kind)->toBe(FieldKind::StringValue);
    expect($byName->get('statusCode')->kind)->toBe(FieldKind::NonNegativeInt);
    expect($byName->get('disposition')->kind)->toBe(FieldKind::EnumSet);
    expect($byName->get('disposition')->allowed)->toBe(['enforce', 'report']);

    expect(collect($specs)->pluck('name')->all())->toBe([
        'documentURL', 'referrer', 'blockedURL', 'effectiveDirective',
        'originalPolicy', 'sourceFile', 'sample',
        'statusCode', 'lineNumber', 'columnNumber', 'disposition',
    ]);
});

test('a consumer type the package does not know returns null, not an empty list', function () {
    expect((new KnownFieldCatalogue)->for('document-policy-violation'))->toBeNull();
});

test('knownTypes lists exactly the four built-in types', function () {
    expect((new KnownFieldCatalogue)->knownTypes())
        ->toEqualCanonicalizing(['csp-violation', 'coep', 'coop', 'network-error']);
});
