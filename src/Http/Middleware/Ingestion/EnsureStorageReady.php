<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Middleware\Ingestion;

use Closure;
use Estin92\SecurityHeaders\Http\Ingestion\ErrorResponse;
use Estin92\SecurityHeaders\Reporting\Ingestion\Events\IngestionStorageUnavailable;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionStorage;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\DatabaseManager;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;
use Throwable;

final class EnsureStorageReady
{
    // Cache only success: a missing table must be rechecked so the endpoint
    // starts working the moment the migration runs, without a restart.
    private bool $ready = false;

    public function __construct(
        private readonly DatabaseManager $database,
        private readonly Dispatcher $events,
        private readonly LoggerInterface $logger,
    ) {}

    /**
     * @param  Closure(Request): SymfonyResponse  $next
     */
    public function handle(Request $request, Closure $next): SymfonyResponse
    {
        if ($this->ready || $this->storageReady()) {
            $this->ready = true;

            return $next($request);
        }

        return $this->storageUnavailable();
    }

    private function storageReady(): bool
    {
        try {
            return $this->database->connection(IngestionStorage::connection())
                ->getSchemaBuilder()
                ->hasTable(IngestionStorage::table());
        } catch (Throwable) {
            // A database that cannot answer is not ready; fail closed rather than crash.
            return false;
        }
    }

    private function storageUnavailable(): SymfonyResponse
    {
        $this->logger->error('Report ingestion is enabled but its table is unreachable or missing — check the connection and run the package migration.', [
            'table' => IngestionStorage::table(),
        ]);

        $this->events->dispatch(new IngestionStorageUnavailable(IngestionStorage::table()));

        return ErrorResponse::serviceUnavailable();
    }
}
