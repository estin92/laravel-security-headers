<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Csp\CspPolicy;
use Estin92\SecurityHeaders\Exceptions\InvalidCspDirective;
use Estin92\SecurityHeaders\Tests\Csp\FakeCspPolicy;

test('it reports whether a nonce is required', function () {
    $without = new FakeCspPolicy(function () {
        $this->directive('default-src', "'self'");
    });

    $with = new FakeCspPolicy(function () {
        $this->directiveWithNonce('script-src', "'self'");
    });

    expect($without->requiresNonce())->toBeFalse();
    expect($with->requiresNonce())->toBeTrue();
});

test('it rejects combining none with other sources', function () {
    $policy = new FakeCspPolicy(function () {
        $this->directive('object-src', "'none'", "'self'");
    });

    expect(fn () => $policy->directives())->toThrow(InvalidCspDirective::class);
});

test('it rejects none combined across separate declarations', function () {
    $policy = new FakeCspPolicy(function () {
        $this->directive('object-src', "'none'");
        $this->directive('object-src', "'self'");
    });

    expect(fn () => $policy->directives())->toThrow(InvalidCspDirective::class);
});

test('it rejects a nonce on a valueless directive', function () {
    $policy = new FakeCspPolicy(function () {
        $this->directiveWithNonce('upgrade-insecure-requests');
    });

    expect(fn () => $policy->directives())->toThrow(InvalidCspDirective::class);
});

test('it does not treat a failed definition as defined', function () {
    $calls = 0;

    $policy = new FakeCspPolicy(function () use (&$calls) {
        $calls++;
        $this->directive('object-src', "'none'", "'self'");
    });

    expect(fn () => $policy->directives())->toThrow(InvalidCspDirective::class);
    expect(fn () => $policy->directives())->toThrow(InvalidCspDirective::class);
    expect($calls)->toBe(2);
});

test('it defines the policy once and memoises the result', function () {
    $calls = 0;

    $policy = new FakeCspPolicy(function () use (&$calls) {
        $calls++;
        $this->directive('default-src', "'self'");
    });

    $policy->directives();
    $policy->directives();
    $policy->requiresNonce();

    expect($calls)->toBe(1);
});

test('it is immutable once defined', function () {
    $policy = new FakeCspPolicy(function () {
        $this->directive('default-src', "'self'");
    });

    $policy->directives();

    expect(fn () => $policy->declareOutsideDefinition('script-src', "'self'"))
        ->toThrow(LogicException::class);
});

test('it rejects declaring a directive while resolving another', function () {
    $policy = new class extends CspPolicy
    {
        protected function define(): void
        {
            $this->directives();
        }
    };

    expect(fn () => $policy->directives())->toThrow(LogicException::class);
});
