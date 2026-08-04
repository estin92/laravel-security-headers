<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator;

class CoopBodyValidator extends AbstractBodyValidator
{
    protected function type(): string
    {
        return 'coop';
    }
}
