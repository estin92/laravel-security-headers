<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Exceptions\InvalidBodyValidatorConfig;
use Estin92\SecurityHeaders\Exceptions\InvalidReportBody;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\BodyValidatorRegistry;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\CoepBodyValidator;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\CoopBodyValidator;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\CspBodyValidator;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\NelBodyValidator;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\ReportBodyValidator;
use Estin92\SecurityHeaders\Support\JsonObject;

function jsonBody(string $json): JsonObject
{
    return JsonObject::fromNative(json_decode($json, false, 512, JSON_THROW_ON_ERROR));
}

test('the CSP validator accepts a well-formed body', function () {
    $validator = new CspBodyValidator;

    $validator->validate(jsonBody('{"documentURL":"https://x/p","statusCode":200,"disposition":"enforce"}'));
})->throwsNoExceptions();

test('the CSP validator accepts a null body', function () {
    (new CspBodyValidator)->validate(null);
})->throwsNoExceptions();

test('the CSP validator preserves and ignores unknown fields', function () {
    (new CspBodyValidator)->validate(jsonBody('{"somethingNew":"whatever"}'));
})->throwsNoExceptions();

test('the CSP validator rejects a non-string URL field', function () {
    expect(fn () => (new CspBodyValidator)->validate(jsonBody('{"documentURL":123}')))
        ->toThrow(InvalidReportBody::class);
});

test('the CSP validator rejects a negative status code', function () {
    expect(fn () => (new CspBodyValidator)->validate(jsonBody('{"statusCode":-1}')))
        ->toThrow(InvalidReportBody::class);
});

test('the CSP validator rejects a non-integer status code', function () {
    expect(fn () => (new CspBodyValidator)->validate(jsonBody('{"statusCode":"200"}')))
        ->toThrow(InvalidReportBody::class);
});

test('the CSP validator rejects a disposition outside the finite set', function () {
    expect(fn () => (new CspBodyValidator)->validate(jsonBody('{"disposition":"maybe"}')))
        ->toThrow(InvalidReportBody::class);
});

test('the CSP validator accepts CSP keyword values in blockedURL', function (string $keyword) {
    (new CspBodyValidator)->validate(jsonBody(json_encode(['blockedURL' => $keyword], JSON_THROW_ON_ERROR)));
})->throwsNoExceptions()->with(['inline', 'eval', 'data', '']);

test('the NEL validator rejects a phase outside the finite set', function () {
    expect(fn () => (new NelBodyValidator)->validate(jsonBody('{"phase":"teleport"}')))
        ->toThrow(InvalidReportBody::class);
});

test('the NEL validator rejects a non-numeric sampling fraction', function () {
    expect(fn () => (new NelBodyValidator)->validate(jsonBody('{"sampling_fraction":"half"}')))
        ->toThrow(InvalidReportBody::class);
});

test('the NEL validator rejects a sampling fraction outside zero to one', function (float $fraction) {
    expect(fn () => (new NelBodyValidator)->validate(jsonBody(json_encode(['sampling_fraction' => $fraction], JSON_THROW_ON_ERROR))))
        ->toThrow(InvalidReportBody::class);
})->with([-0.1, 1.5]);

test('the NEL validator accepts a sampling fraction within zero to one', function (float $fraction) {
    (new NelBodyValidator)->validate(jsonBody(json_encode(['sampling_fraction' => $fraction], JSON_THROW_ON_ERROR)));
})->throwsNoExceptions()->with([0.0, 0.5, 1.0]);

test('the NEL validator rejects a non-negative elapsed time that is negative', function () {
    expect(fn () => (new NelBodyValidator)->validate(jsonBody('{"elapsed_time":-5}')))
        ->toThrow(InvalidReportBody::class);
});

test('the NEL validator rejects a header map that is not string to string', function () {
    expect(fn () => (new NelBodyValidator)->validate(jsonBody('{"request_headers":{"x":5}}')))
        ->toThrow(InvalidReportBody::class);
});

test('the NEL validator accepts a header map of strings and string lists', function () {
    (new NelBodyValidator)->validate(jsonBody('{"request_headers":{"accept":"text/html","x":["a","b"]}}'));
})->throwsNoExceptions();

test('the COEP validator rejects a non-string disposition', function () {
    expect(fn () => (new CoepBodyValidator)->validate(jsonBody('{"disposition":5}')))
        ->toThrow(InvalidReportBody::class);
});

test('the COOP validator accepts a well-formed body', function () {
    (new CoopBodyValidator)->validate(jsonBody('{"type":"navigation","disposition":"enforce"}'));
})->throwsNoExceptions();

test('the COOP validator rejects a non-string field', function () {
    expect(fn () => (new CoopBodyValidator)->validate(jsonBody('{"effectivePolicy":5}')))
        ->toThrow(InvalidReportBody::class);
});

test('the NEL validator rejects a header map that is not an object', function () {
    expect(fn () => (new NelBodyValidator)->validate(jsonBody('{"request_headers":"not-a-map"}')))
        ->toThrow(InvalidReportBody::class);
});

test('the NEL validator rejects a header list holding a non-string', function () {
    expect(fn () => (new NelBodyValidator)->validate(jsonBody('{"request_headers":{"x":["ok",5]}}')))
        ->toThrow(InvalidReportBody::class);
});

test('the registry selects the package validator by report-type value', function () {
    $registry = new BodyValidatorRegistry([], app());

    expect($registry->for('csp-violation'))->toBeInstanceOf(CspBodyValidator::class);
    expect($registry->for('network-error'))->toBeInstanceOf(NelBodyValidator::class);
});

test('the registry uses a consumer validator for a non-built-in type', function () {
    $registry = new BodyValidatorRegistry(['document-policy-violation' => PassthroughValidator::class], app());

    expect($registry->for('document-policy-violation'))->toBeInstanceOf(PassthroughValidator::class);
});

test('a consumer validator for a built-in type is a config error', function () {
    expect(fn () => new BodyValidatorRegistry(['csp-violation' => PassthroughValidator::class], app()))
        ->toThrow(InvalidBodyValidatorConfig::class);
});

test('a type with no validator falls back to accepting any object', function () {
    $registry = new BodyValidatorRegistry([], app());

    $registry->for('document-policy-violation')->validate(jsonBody('{"anything":true}'));
})->throwsNoExceptions();

test('a consumer entry that does not name a validator class is a config error', function () {
    expect(fn () => new BodyValidatorRegistry(['document-policy-violation' => 'NotARealClass'], app()))
        ->toThrow(InvalidBodyValidatorConfig::class);
});

test('a container binding that is not a validator is rejected', function () {
    app()->bind(CspBodyValidator::class, fn () => new stdClass);
    $registry = new BodyValidatorRegistry([], app());

    expect(fn () => $registry->for('csp-violation'))->toThrow(InvalidBodyValidatorConfig::class);
});

class PassthroughValidator implements ReportBodyValidator
{
    public function validate(?JsonObject $body): void {}
}
