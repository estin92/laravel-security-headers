<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Console;

use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\PrunePhase;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportPruneFailed;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\ReportsPruned;
use Illuminate\Console\Command;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Psr\Log\LoggerInterface;
use Throwable;

final class PruneReportsCommand extends Command
{
    private const DELETE_BATCH_SIZE = 1000;

    protected $signature = 'security-headers:prune-reports';

    protected $description = 'Delete security reports past the retention window and row cap.';

    public function handle(Dispatcher $events, LoggerInterface $logger): int
    {
        $startedAt = microtime(true);
        $phase = PrunePhase::Expired;

        try {
            $expired = $this->deleteExpired();

            $phase = PrunePhase::Excess;
            $excess = $this->trimToMaxRows();
        } catch (Throwable $e) {
            $logger->error('Pruning security reports failed.', ['phase' => $phase->value, 'exception' => $e::class]);
            $events->dispatch(new ReportPruneFailed($phase, $e::class));

            return self::FAILURE;
        }

        $remaining = SecurityReport::query()->count();
        $events->dispatch(new ReportsPruned($expired, $excess, $remaining, microtime(true) - $startedAt));

        $this->info("Pruned {$expired} expired and {$excess} surplus reports. {$remaining} remain.");

        return self::SUCCESS;
    }

    private function deleteExpired(): int
    {
        $days = $this->configInt('retention.days', 30);
        $cutoff = Carbon::now()->subDays($days);

        return $this->deleteInBatches(SecurityReport::query()->where('received_at', '<', $cutoff));
    }

    private function trimToMaxRows(): int
    {
        $maxRows = $this->configInt('retention.max_rows', 100000);
        $surplus = SecurityReport::query()->count() - $maxRows;

        if ($surplus <= 0) {
            return 0;
        }

        return $this->deleteInBatches(SecurityReport::query(), $surplus);
    }

    /**
     * Delete the oldest matching rows in bounded batches, each its own short autocommit
     * statement so live ingestion at the newest rows keeps flowing.
     *
     * @param  Builder<SecurityReport>  $query  the rows eligible for deletion
     * @param  ?int  $limit  stop after this many rows, or null to delete every match
     */
    private function deleteInBatches(Builder $query, ?int $limit = null): int
    {
        $deleted = 0;

        while ($limit === null || $deleted < $limit) {
            $take = $limit === null ? self::DELETE_BATCH_SIZE : min(self::DELETE_BATCH_SIZE, $limit - $deleted);

            $ids = (clone $query)
                ->orderBy('received_at')
                ->orderBy('id')
                ->limit($take)
                ->pluck('id')
                ->all();

            if ($ids === []) {
                break;
            }

            $removed = SecurityReport::query()->whereIntegerInRaw('id', $ids)->delete();

            $deleted += is_int($removed) ? $removed : 0;
        }

        return $deleted;
    }

    private function configInt(string $key, int $default): int
    {
        // Boot validation guarantees these are ints; the default only covers a config read that finds nothing.
        $value = config('security-headers.reporting.ingestion.'.$key, $default);

        return is_int($value) ? $value : $default;
    }
}
