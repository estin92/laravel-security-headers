<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Tests\Http\WithIngestionEnabled;
use Estin92\SecurityHeaders\Tests\Http\WithoutAutoRegistration;
use Estin92\SecurityHeaders\Tests\Reporting\Ingestion\IngestionTestCase;
use Estin92\SecurityHeaders\Tests\TestCase;

// Http tests disable auto-registration so the route-attached middleware runs
// once, not twice. Bindings cannot overlap, so each file is bound explicitly.
uses(WithoutAutoRegistration::class)->in(
    __DIR__.'/Http/ApplySecurityHeadersTest.php',
    __DIR__.'/Http/Ingestion/ReportMiddlewareTest.php',
    __DIR__.'/Http/Ingestion/RouteDisabledTest.php',
);
uses(WithIngestionEnabled::class)->in(__DIR__.'/Http/Ingestion/ReportIngestionRouteTest.php');
// Ingestion tests enable the feature at boot so the package migration loads;
// the emission tests below do not need it.
// Ingestion tests enable the feature at boot so the package migration loads.
// ConfigDefaultsTest is excluded: it asserts the shipped default (disabled).
uses(IngestionTestCase::class)->in(
    __DIR__.'/Console',
    __DIR__.'/Reporting/Ingestion/BodyValidationTest.php',
    __DIR__.'/Reporting/Ingestion/EventsTest.php',
    __DIR__.'/Reporting/Ingestion/IncidentFingerprintTest.php',
    __DIR__.'/Reporting/Ingestion/IngestionBootGateTest.php',
    __DIR__.'/Reporting/Ingestion/IngestionConfigValidatorTest.php',
    __DIR__.'/Reporting/Ingestion/IngestionConnectionTest.php',
    __DIR__.'/Reporting/Ingestion/IngestionPipelineTest.php',
    __DIR__.'/Reporting/Ingestion/JsonObjectCastTest.php',
    __DIR__.'/Reporting/Ingestion/LegacyCspReportDecoderTest.php',
    __DIR__.'/Reporting/Ingestion/ModernReportDecoderTest.php',
    __DIR__.'/Reporting/Ingestion/NormalizedReportTest.php',
    __DIR__.'/Reporting/Ingestion/RejectionReasonTest.php',
    __DIR__.'/Reporting/Ingestion/ReportTypeResolverTest.php',
    __DIR__.'/Reporting/Ingestion/ReportTypeTest.php',
    __DIR__.'/Reporting/Ingestion/SanitizerTest.php',
    __DIR__.'/Reporting/Ingestion/SecurityReportPersistenceTest.php',
    __DIR__.'/Reporting/Ingestion/StoragePolicyTest.php',
);
uses(TestCase::class)->in(
    __DIR__.'/Coep',
    __DIR__.'/Coop',
    __DIR__.'/Csp',
    __DIR__.'/Headers',
    __DIR__.'/Nel',
    __DIR__.'/PermissionsPolicy',
    __DIR__.'/Reporting/Ingestion/ConfigDefaultsTest.php',
    __DIR__.'/Reporting/ReportingEndpointsCompilerTest.php',
    __DIR__.'/Reporting/ReportingEndpointTest.php',
    __DIR__.'/Reporting/ReportToCompilerTest.php',
    __DIR__.'/Reporting/ReportToDestinationTest.php',
    __DIR__.'/Reporting/ReportToEndpointTest.php',
    __DIR__.'/Reporting/ReportToGroupTest.php',
    __DIR__.'/Support',
    __DIR__.'/AutoRegistrationTest.php',
    __DIR__.'/ServiceProviderTest.php',
);
