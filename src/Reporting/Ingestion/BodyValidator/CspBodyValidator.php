<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator;

class CspBodyValidator extends AbstractBodyValidator
{
    protected function type(): string
    {
        return 'csp-violation';
    }
}
