<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\Events;

enum ProcessingStage: string
{
    case ConsumerValidation = 'consumer_validation';
}
