<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Controllers;

use Estin92\SecurityHeaders\Http\Ingestion\ErrorResponse;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionContext;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionPipeline;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Symfony\Component\HttpFoundation\Response;

final class ReportIngestionController
{
    public function __construct(private readonly IngestionPipeline $pipeline) {}

    public function __invoke(Request $request): Response
    {
        $context = new IngestionContext(
            $request->ip(),
            $request->userAgent(),
            Carbon::now()->toDateTimeImmutable(),
        );

        $result = $this->pipeline->ingest(
            (string) $request->headers->get('Content-Type', ''),
            $request->getContent(),
            $context,
        );

        if ($result->isAccepted() || $result->errorCode === null) {
            return new Response(status: 204);
        }

        return ErrorResponse::code($result->errorCode, $result->status);
    }
}
