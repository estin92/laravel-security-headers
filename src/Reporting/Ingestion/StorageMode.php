<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

enum StorageMode: string
{
    case Sanitized = 'sanitized';
    case Raw = 'raw';
}
