<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting;

final class ReportToCompiler
{
    /**
     * @param  array<string, ReportToGroup>  $groups  Insertion order is preserved.
     */
    public function compile(array $groups): string
    {
        $members = [];

        foreach ($groups as $group) {
            $members[] = json_encode($this->group($group), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        }

        return implode(', ', $members);
    }

    /**
     * @return array<string, mixed>
     */
    private function group(ReportToGroup $group): array
    {
        $object = ['group' => $group->group, 'max_age' => $group->maxAge];

        if ($group->includeSubdomains !== null) {
            $object['include_subdomains'] = $group->includeSubdomains;
        }

        $object['endpoints'] = array_map(fn (ReportToEndpoint $endpoint): array => $this->endpoint($endpoint), $group->endpoints);

        return $object;
    }

    /**
     * @return array<string, mixed>
     */
    private function endpoint(ReportToEndpoint $endpoint): array
    {
        $object = ['url' => $endpoint->endpoint->reportUri()];

        if ($endpoint->priority !== null) {
            $object['priority'] = $endpoint->priority;
        }

        if ($endpoint->weight !== null) {
            $object['weight'] = $endpoint->weight;
        }

        return $object;
    }
}
