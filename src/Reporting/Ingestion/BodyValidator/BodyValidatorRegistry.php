<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator;

use Estin92\SecurityHeaders\Exceptions\InvalidBodyValidatorConfig;
use Illuminate\Contracts\Container\Container;

final class BodyValidatorRegistry
{
    /**
     * @var array<string, class-string<ReportBodyValidator>>
     */
    private const BUILT_IN = [
        'csp-violation' => CspBodyValidator::class,
        'coep' => CoepBodyValidator::class,
        'coop' => CoopBodyValidator::class,
        'network-error' => NelBodyValidator::class,
    ];

    /**
     * @var array<string, class-string<ReportBodyValidator>>
     */
    private readonly array $consumerValidators;

    /**
     * @param  array<mixed>  $consumerValidators
     */
    public function __construct(array $consumerValidators, private readonly Container $container)
    {
        $this->consumerValidators = $this->validateConsumerMap($consumerValidators);
    }

    public function for(string $type): ReportBodyValidator
    {
        $class = self::BUILT_IN[$type] ?? $this->consumerValidators[$type] ?? AcceptAnyBodyValidator::class;

        $validator = $this->container->make($class);

        if (! $validator instanceof ReportBodyValidator) {
            throw InvalidBodyValidatorConfig::notAValidator($type);
        }

        return $validator;
    }

    /**
     * @param  array<mixed>  $consumerValidators
     * @return array<string, class-string<ReportBodyValidator>>
     */
    private function validateConsumerMap(array $consumerValidators): array
    {
        $validated = [];

        foreach ($consumerValidators as $type => $class) {
            $type = (string) $type;

            if (isset(self::BUILT_IN[$type])) {
                throw InvalidBodyValidatorConfig::builtInType($type);
            }

            if (! is_string($class) || ! is_a($class, ReportBodyValidator::class, true)) {
                throw InvalidBodyValidatorConfig::notAValidator($type);
            }

            $validated[$type] = $class;
        }

        return $validated;
    }
}
