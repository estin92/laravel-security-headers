<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator;

class NelBodyValidator extends AbstractBodyValidator
{
    protected function type(): string
    {
        return 'network-error';
    }
}
