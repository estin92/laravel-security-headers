<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

final class IngestionStorage
{
    public static function table(): string
    {
        $table = config('security-headers.reporting.ingestion.database.table');

        return is_string($table) ? $table : 'security_reports';
    }

    public static function connection(): ?string
    {
        $connection = config('security-headers.reporting.ingestion.database.connection');

        return is_string($connection) ? $connection : null;
    }
}
