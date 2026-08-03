<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use BackedEnum;
use Estin92\SecurityHeaders\Exceptions\InvalidReportSubmission;
use Estin92\SecurityHeaders\Exceptions\InvalidReportTypeEnum;
use ReflectionEnum;
use ReflectionEnumBackedCase;

final class ReportTypeResolver
{
    /**
     * @param  class-string<BackedEnum&ReportTypeContract>  $enumClass
     */
    private function __construct(private readonly string $enumClass) {}

    public static function forEnum(string $enumClass): self
    {
        if (! enum_exists($enumClass)) {
            throw InvalidReportTypeEnum::notAnEnum($enumClass);
        }

        $enum = new ReflectionEnum($enumClass);

        if ((string) $enum->getBackingType() !== 'string') {
            throw InvalidReportTypeEnum::notStringBacked($enumClass);
        }

        if (! $enum->implementsInterface(ReportTypeContract::class)) {
            throw InvalidReportTypeEnum::missingContract($enumClass);
        }

        foreach ($enum->getCases() as $case) {
            /** @var ReflectionEnumBackedCase $case */
            self::guardValue($enumClass, (string) $case->getBackingValue());
        }

        /** @var class-string<BackedEnum&ReportTypeContract> $enumClass */
        return new self($enumClass);
    }

    /**
     * @throws InvalidReportSubmission
     */
    public function resolve(string $type): ReportTypeContract&BackedEnum
    {
        $case = $this->enumClass::tryFrom($type);

        if (! $case instanceof ReportTypeContract) {
            throw InvalidReportSubmission::unacceptedType($type);
        }

        return $case;
    }

    /**
     * @param  class-string  $enumClass
     */
    private static function guardValue(string $enumClass, string $value): void
    {
        if (strlen($value) > 64 || preg_match('/\A[a-z][a-z0-9-]*\z/', $value) !== 1) {
            throw InvalidReportTypeEnum::invalidValue($enumClass, $value);
        }
    }
}
