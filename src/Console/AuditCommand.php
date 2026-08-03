<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Console;

use Estin92\SecurityHeaders\Exceptions\InvalidIngestionConfig;
use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionConfigValidator;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionStorage;
use Illuminate\Console\Command;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Carbon;

final class AuditCommand extends Command
{
    protected $signature = 'security-headers:audit';

    protected $description = 'Check the report-ingestion configuration and storage before relying on it in production.';

    public function handle(IngestionConfigValidator $validator, DatabaseManager $database): int
    {
        $config = config('security-headers.reporting.ingestion');
        $config = is_array($config) ? $config : [];

        $hasHardFinding = false;
        $configValid = true;

        try {
            $validator->validate($config);
        } catch (InvalidIngestionConfig $e) {
            $this->error($e->getMessage());
            $hasHardFinding = true;
            $configValid = false;
        }

        if (! $this->tableExists($database)) {
            $this->error('The ingestion table '.IngestionStorage::table().' is missing — run the package migration.');
            $hasHardFinding = true;
        } elseif ($configValid) {
            $this->reportRetention(IngestionConfigValidator::section($config, 'retention'));
        } else {
            $this->warn('Retention configuration is invalid — retention-state analysis was not performed.');
        }

        $this->warnRawMode(IngestionConfigValidator::section($config, 'storage'));
        $this->warnUnlimited(IngestionConfigValidator::section($config, 'rate_limiting'));

        if ($hasHardFinding) {
            return self::FAILURE;
        }

        $this->info('Report ingestion configuration and storage look sound.');

        return self::SUCCESS;
    }

    private function tableExists(DatabaseManager $database): bool
    {
        return $database->connection(IngestionStorage::connection())
            ->getSchemaBuilder()
            ->hasTable(IngestionStorage::table());
    }

    /**
     * @param  array<mixed>  $retention
     */
    private function reportRetention(array $retention): void
    {
        // Reached only when config validation passed, so days is a validated positive int.
        $days = is_int($retention['days'] ?? null) ? $retention['days'] : 30;
        $cutoff = Carbon::now()->subDays($days);

        $expired = SecurityReport::query()->where('received_at', '<', $cutoff)->exists();

        if ($expired) {
            $this->warn("Reports older than the {$days}-day retention window are still stored — is the prune schedule running?");

            return;
        }

        $this->info('Retention: no current retention violation.');
    }

    /**
     * @param  array<mixed>  $storage
     */
    private function warnRawMode(array $storage): void
    {
        if (($storage['mode'] ?? null) === 'raw' && ($storage['raw_acknowledged'] ?? null) !== true) {
            $this->warn('Storage is in raw mode, keeping unsanitized report data. Set raw_acknowledged to silence this.');
        }
    }

    /**
     * @param  array<mixed>  $rateLimiting
     */
    private function warnUnlimited(array $rateLimiting): void
    {
        if (($rateLimiting['enabled'] ?? null) === false && ($rateLimiting['external_limiting_acknowledged'] ?? null) !== true) {
            $this->warn('Built-in rate limiting is off and nothing acknowledges an external limiter. Set external_limiting_acknowledged if a proxy handles it.');
        }
    }
}
