<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator;

use Estin92\SecurityHeaders\Support\JsonObject;

class CspBodyValidator extends AbstractBodyValidator
{
    protected function type(): string
    {
        return 'csp-violation';
    }

    protected function validateFields(JsonObject $body): void
    {
        foreach (['documentURL', 'referrer', 'blockedURL', 'effectiveDirective', 'originalPolicy', 'sourceFile', 'sample'] as $field) {
            $this->assertString($body, $field);
        }

        foreach (['statusCode', 'lineNumber', 'columnNumber'] as $field) {
            $this->assertNonNegativeInt($body, $field);
        }

        $this->assertInSet($body, 'disposition', ['enforce', 'report']);
    }
}
