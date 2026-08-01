<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Nel;

use Estin92\SecurityHeaders\Exceptions\InvalidNel;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;
use Estin92\SecurityHeaders\Support\Fraction;
use Estin92\SecurityHeaders\Support\NonNegativeInt;

final readonly class NelPolicy
{
    private function __construct(
        public ?string $reportToGroupKey,
        public int $maxAge,
        public ?bool $includeSubdomains,
        public ?float $successFraction,
        public ?float $failureFraction,
    ) {}

    public static function fromConfig(mixed $definition): self
    {
        if (! is_array($definition)) {
            throw InvalidNel::notAnArray($definition);
        }

        foreach (array_keys($definition) as $key) {
            if (! in_array($key, ['report_to_group', 'max_age', 'include_subdomains', 'success_fraction', 'failure_fraction'], true)) {
                throw InvalidNel::unknownKey((string) $key);
            }
        }

        $maxAge = self::maxAge($definition);
        $includeSubdomains = self::includeSubdomains($definition);
        $successFraction = self::fraction($definition, 'success_fraction');
        $failureFraction = self::fraction($definition, 'failure_fraction');

        if ($maxAge === 0) {
            self::assertRemovalDefaults($definition, $includeSubdomains, $successFraction, $failureFraction);

            return new self(null, 0, null, null, null);
        }

        return new self(
            self::reportToGroupKey($definition),
            $maxAge,
            $includeSubdomains,
            $successFraction,
            $failureFraction,
        );
    }

    public function isRemoval(): bool
    {
        return $this->maxAge === 0;
    }

    public function assertCompatibleWith(ReportToGroup $group): void
    {
        if ($group->isRemoval()) {
            throw InvalidNel::groupIsRemoval($group->group);
        }

        if ($group->maxAge < $this->maxAge) {
            throw InvalidNel::groupLifetimeTooShort($group->group);
        }

        if ($this->includeSubdomains === true && $group->includeSubdomains !== true) {
            throw InvalidNel::groupSubdomainsMismatch($group->group);
        }
    }

    /**
     * @param  array<mixed>  $definition
     */
    private static function maxAge(array $definition): int
    {
        if (! array_key_exists('max_age', $definition)) {
            throw InvalidNel::missingMaxAge();
        }

        return NonNegativeInt::parse($definition['max_age']) ?? throw InvalidNel::invalidMaxAge($definition['max_age']);
    }

    /**
     * @param  array<mixed>  $definition
     */
    private static function reportToGroupKey(array $definition): string
    {
        $value = $definition['report_to_group'] ?? null;

        if ($value === null || $value === '') {
            throw InvalidNel::missingReportToGroup();
        }

        if (! is_string($value)) {
            throw InvalidNel::invalidReportToGroup($value);
        }

        return $value;
    }

    /**
     * @param  array<mixed>  $definition
     */
    private static function includeSubdomains(array $definition): ?bool
    {
        if (! array_key_exists('include_subdomains', $definition) || $definition['include_subdomains'] === null) {
            return null;
        }

        $value = filter_var($definition['include_subdomains'], FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);

        return $value ?? throw InvalidNel::invalidIncludeSubdomains($definition['include_subdomains']);
    }

    /**
     * @param  array<mixed>  $definition
     */
    private static function fraction(array $definition, string $key): ?float
    {
        if (! array_key_exists($key, $definition) || $definition[$key] === null) {
            return null;
        }

        $value = Fraction::parse($definition[$key]);

        if ($value !== null) {
            return $value;
        }

        throw $key === 'success_fraction'
            ? InvalidNel::invalidSuccessFraction($definition[$key])
            : InvalidNel::invalidFailureFraction($definition[$key]);
    }

    /**
     * @param  array<mixed>  $definition
     */
    private static function assertRemovalDefaults(array $definition, ?bool $includeSubdomains, ?float $successFraction, ?float $failureFraction): void
    {
        if (($definition['report_to_group'] ?? null) !== null) {
            throw InvalidNel::removalFieldNotDefault('report_to_group');
        }

        if ($includeSubdomains === true) {
            throw InvalidNel::removalFieldNotDefault('include_subdomains');
        }

        if ($successFraction !== null && $successFraction !== 0.0) {
            throw InvalidNel::removalFieldNotDefault('success_fraction');
        }

        if ($failureFraction !== null && $failureFraction !== 1.0) {
            throw InvalidNel::removalFieldNotDefault('failure_fraction');
        }
    }
}
