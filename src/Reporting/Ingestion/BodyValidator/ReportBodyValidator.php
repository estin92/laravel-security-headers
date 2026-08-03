<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator;

use Estin92\SecurityHeaders\Exceptions\InvalidReportBody;
use Estin92\SecurityHeaders\Support\JsonObject;

interface ReportBodyValidator
{
    /**
     * @throws InvalidReportBody
     */
    public function validate(?JsonObject $body): void;
}
