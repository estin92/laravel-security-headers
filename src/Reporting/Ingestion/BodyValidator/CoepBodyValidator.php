<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator;

use Estin92\SecurityHeaders\Support\JsonObject;

class CoepBodyValidator extends AbstractBodyValidator
{
    protected function type(): string
    {
        return 'coep';
    }

    protected function validateFields(JsonObject $body): void
    {
        foreach (['type', 'blockedURL', 'destination'] as $field) {
            $this->assertString($body, $field);
        }

        $this->assertInSet($body, 'disposition', ['enforce', 'reporting']);
    }
}
