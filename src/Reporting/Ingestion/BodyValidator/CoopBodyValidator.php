<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator;

use Estin92\SecurityHeaders\Support\JsonObject;

class CoopBodyValidator extends AbstractBodyValidator
{
    protected function type(): string
    {
        return 'coop';
    }

    protected function validateFields(JsonObject $body): void
    {
        foreach (['type', 'disposition', 'effectivePolicy', 'referrer'] as $field) {
            $this->assertString($body, $field);
        }
    }
}
