<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidReportSubmission;
use Estin92\SecurityHeaders\Exceptions\InvalidReportTypeEnum;
use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeResolver;
use Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures\BadGrammarReportType;
use Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures\IntBackedReportType;
use Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures\MissingContractReportType;
use Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures\NotAnEnum;
use Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures\ReportTypeWithTooLongValue;
use Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures\UnbackedReportType;
use Estin92\SecurityHeaders\Tests\Reporting\Ingestion\Fixtures\ValidConsumerReportType;

test('it resolves a type the configured enum accepts', function () {
    $resolver = ReportTypeResolver::forEnum(ValidConsumerReportType::class);

    expect($resolver->resolve('document-policy-violation'))
        ->toBe(ValidConsumerReportType::DocumentPolicyViolation);
});

test('it resolves against the package default enum', function () {
    $resolver = ReportTypeResolver::forEnum(ReportType::class);

    expect($resolver->resolve('coop'))->toBe(ReportType::Coop);
});

test('a type the enum does not accept is rejected', function () {
    $resolver = ReportTypeResolver::forEnum(ValidConsumerReportType::class);

    expect(fn () => $resolver->resolve('network-error'))
        ->toThrow(
            InvalidReportSubmission::class,
        );
});

test('the rejection reason for an unaccepted type is a 422', function () {
    $resolver = ReportTypeResolver::forEnum(ValidConsumerReportType::class);

    try {
        $resolver->resolve('network-error');
    } catch (InvalidReportSubmission $e) {
        expect($e->reason)->toBe(RejectionReason::UnacceptedReportType);
        expect($e->reason->status())->toBe(422);
        expect($e->offendingType)->toBe('network-error');

        return;
    }

    $this->fail('Expected InvalidReportSubmission.');
});

test('a configured class that is not the right kind of enum is refused at boot', function (string $class) {
    expect(fn () => ReportTypeResolver::forEnum($class))
        ->toThrow(InvalidReportTypeEnum::class);
})->with([
    'not an enum' => [NotAnEnum::class],
    'not string-backed' => [UnbackedReportType::class],
    'missing the contract' => [MissingContractReportType::class],
    'a value breaking the grammar' => [BadGrammarReportType::class],
    'a value over 64 bytes' => [ReportTypeWithTooLongValue::class],
    'an int-backed enum' => [IntBackedReportType::class],
    'a class that does not exist' => ['Estin92\\SecurityHeaders\\Tests\\Nope'],
]);
