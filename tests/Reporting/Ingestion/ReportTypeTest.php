<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\Ingestion\ReportProtocol;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportTypeContract;

test('the default enum only contains types the package emits', function () {
    expect(array_map(fn ($c) => $c->value, ReportType::cases()))
        ->toBe(['csp-violation', 'coep', 'coop', 'network-error']);
});

test('every default type implements the contract with a label', function () {
    foreach (ReportType::cases() as $case) {
        expect($case)->toBeInstanceOf(ReportTypeContract::class);
        expect($case->label())->toBeString()->not->toBe('');
    }
});

test('report protocol only names the two formats we decode', function () {
    expect(array_map(fn ($c) => $c->value, ReportProtocol::cases()))
        ->toBe(['reporting-api', 'legacy-csp-report-uri']);
});
