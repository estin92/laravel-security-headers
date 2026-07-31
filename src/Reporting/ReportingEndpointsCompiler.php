<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting;

final class ReportingEndpointsCompiler
{
    /**
     * @param  array<string, ReportingEndpoint>  $endpoints  Insertion order is preserved.
     */
    public function compile(array $endpoints): string
    {
        $members = [];

        foreach ($endpoints as $endpoint) {
            $members[] = "{$endpoint->name}=\"{$endpoint->url}\"";
        }

        return implode(', ', $members);
    }
}
