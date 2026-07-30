<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Csp\CspPolicy;
use Estin92\SecurityHeaders\Csp\CspPolicyResolver;
use Estin92\SecurityHeaders\Csp\Keyword;
use Estin92\SecurityHeaders\Csp\StrictPolicy;
use Estin92\SecurityHeaders\Exceptions\InvalidCspPolicy;

class DependentPolicy extends CspPolicy
{
    public function __construct(private string $host) {}

    protected function define(): void
    {
        $this->directive('connect-src', Keyword::Self, $this->host);
    }
}

function resolver(): CspPolicyResolver
{
    return new CspPolicyResolver(app());
}

test('it resolves a policy class into an instance', function () {
    expect(resolver()->resolve(StrictPolicy::class))->toBeInstanceOf(StrictPolicy::class);
});

test('it resolves a policy that has constructor dependencies', function () {
    app()->when(DependentPolicy::class)
        ->needs('$host')
        ->give('https://cdn.example.com');

    $policy = resolver()->resolve(DependentPolicy::class);

    expect($policy)->toBeInstanceOf(DependentPolicy::class);
    expect($policy->directives()['connect-src'])->toContain('https://cdn.example.com');
});

test('it rejects a value that is not a string', function (mixed $value) {
    expect(fn () => resolver()->resolve($value))->toThrow(InvalidCspPolicy::class);
})->with([
    'null' => [null],
    'integer' => [123],
    'array' => [[StrictPolicy::class]],
]);

test('it rejects a class that does not exist', function () {
    expect(fn () => resolver()->resolve('App\\Nope'))->toThrow(InvalidCspPolicy::class);
});

test('it rejects a class that is not a CSP policy', function () {
    expect(fn () => resolver()->resolve(stdClass::class))->toThrow(InvalidCspPolicy::class);
});

test('it rejects a container binding that resolves to the wrong type', function () {
    app()->bind(StrictPolicy::class, fn () => new stdClass);

    expect(fn () => resolver()->resolve(StrictPolicy::class))->toThrow(InvalidCspPolicy::class);
});
