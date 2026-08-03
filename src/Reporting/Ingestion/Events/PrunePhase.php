<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\Events;

enum PrunePhase: string
{
    case Expired = 'expired';
    case Excess = 'excess';
}
