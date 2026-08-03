<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

interface ReportTypeContract
{
    public function label(): string;
}
