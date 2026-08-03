<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\Events;

use InvalidArgumentException;

final readonly class SecurityReportsReceived
{
    /**
     * @param  list<ReceivedSecurityReport>  $reports
     */
    public function __construct(public array $reports)
    {
        if ($reports === []) {
            throw new InvalidArgumentException('SecurityReportsReceived needs at least one report.');
        }
    }

    public function count(): int
    {
        return count($this->reports);
    }
}
