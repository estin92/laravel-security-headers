<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator;

use Estin92\SecurityHeaders\Support\JsonObject;

// A type with no rules of its own
class AcceptAnyBodyValidator implements ReportBodyValidator
{
    public function validate(?JsonObject $body): void {}
}
