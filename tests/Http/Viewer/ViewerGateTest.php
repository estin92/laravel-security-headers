<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Http\Viewer\ViewerGate;
use Illuminate\Support\Facades\Gate;

test('with no ability defined, local allows even a guest', function () {
    app()['env'] = 'local';

    expect(ViewerGate::allows(null))->toBeTrue();
});

test('with no ability defined, production denies', function () {
    app()['env'] = 'production';

    expect(ViewerGate::allows(null))->toBeFalse();
});

test('a defined ability that denies denies an authenticated user in local too', function () {
    app()['env'] = 'local';
    Gate::define(ViewerGate::ABILITY, fn ($user) => false);

    expect(ViewerGate::allows(fakeViewer()))->toBeFalse();
});

test('a defined ability that allows an authenticated user allows in production', function () {
    app()['env'] = 'production';
    Gate::define(ViewerGate::ABILITY, fn ($user) => true);

    expect(ViewerGate::allows(fakeViewer()))->toBeTrue();
});

test('a defined ability that denies is not rescued by the local guest fallback', function () {
    app()['env'] = 'local';
    Gate::define(ViewerGate::ABILITY, fn ($user) => false);

    expect(ViewerGate::allows(null))->toBeFalse();
});

test('the local fallback resolves from environment, not debug mode', function () {
    app()['env'] = 'production';
    config()->set('app.debug', true);

    expect(ViewerGate::allows(null))->toBeFalse();
});
