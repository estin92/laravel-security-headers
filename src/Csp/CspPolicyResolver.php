<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Csp;

use Estin92\SecurityHeaders\Exceptions\InvalidCspPolicy;
use Illuminate\Contracts\Container\Container;

final readonly class CspPolicyResolver
{
    public function __construct(private Container $container) {}

    public function resolve(mixed $configuredPolicy): CspPolicy
    {
        $class = $this->validatePolicyClass($configuredPolicy);

        $policy = $this->container->make($class);

        if (! $policy instanceof CspPolicy) {
            throw InvalidCspPolicy::resolvedToWrongType($class, get_debug_type($policy));
        }

        return $policy;
    }

    /**
     * @return class-string<CspPolicy>
     */
    private function validatePolicyClass(mixed $value): string
    {
        if (! is_string($value) || ! is_a($value, CspPolicy::class, true)) {
            throw InvalidCspPolicy::configuredValueIsInvalid($value);
        }

        return $value;
    }
}
