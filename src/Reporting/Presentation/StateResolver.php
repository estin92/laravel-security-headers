<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Presentation;

use Estin92\SecurityHeaders\Models\SecurityReport;
use Estin92\SecurityHeaders\Reporting\Fields\FieldSpec;
use Estin92\SecurityHeaders\Reporting\Fields\KnownFieldCatalogue;
use stdClass;

final class StateResolver
{
    private const CONTEXT_FIELDS = ['url', 'client_ip', 'request_user_agent', 'reported_user_agent'];

    public function __construct(private readonly KnownFieldCatalogue $catalogue) {}

    /**
     * @return list<PresentationNode>
     */
    public function resolve(SecurityReport $report, ResolverCaps $caps): array
    {
        $actions = $this->indexActions($report->sanitization_actions);
        $budget = $caps->maxNodes;

        $nodes = [];

        foreach (self::CONTEXT_FIELDS as $field) {
            $nodes[] = $this->contextNode($field, $report->{$field}, $actions, $caps);
        }

        $nodes[] = $this->bodyNode($report, $actions, $caps, $budget);

        return $nodes;
    }

    /**
     * @param  list<array{path: list<string|int>, action: string}>  $actions
     * @return array<string, string>
     */
    private function indexActions(array $actions): array
    {
        $indexed = [];

        foreach ($actions as $action) {
            $indexed[$this->pathKey($action['path'])] = $action['action'];
        }

        return $indexed;
    }

    /**
     * @param  array<string, string>  $actions
     */
    private function contextNode(string $key, mixed $rawValue, array $actions, ResolverCaps $caps): PresentationNode
    {
        return $this->scalarNode([$key], $key, $rawValue, $actions[$this->pathKey([$key])] ?? null, $caps);
    }

    /**
     * @param  array<string, string>  $actions
     */
    private function bodyNode(SecurityReport $report, array $actions, ResolverCaps $caps, int &$budget): PresentationNode
    {
        $native = $report->body?->toNative() ?? new stdClass;
        $specs = $this->catalogue->for($report->type);

        [$children, $omitted] = $specs === null
            ? $this->consumerChildren(['body'], $native, $actions, $caps, 1, $budget)
            : $this->catalogueChildren(['body'], $native, $specs, $actions, $caps, $budget);

        return new PresentationNode(
            path: ['body'],
            key: 'body',
            state: FieldState::Present,
            value: null,
            valueType: 'object',
            action: null,
            truncated: false,
            children: $children,
            childrenOmitted: $omitted,
        );
    }

    /**
     * @param  list<string|int>  $parentPath
     * @param  list<FieldSpec>  $specs
     * @param  array<string, string>  $actions
     * @return array{0: list<PresentationNode>, 1: int}
     */
    private function catalogueChildren(array $parentPath, stdClass $native, array $specs, array $actions, ResolverCaps $caps, int &$budget): array
    {
        $children = [];
        $covered = [];
        $omitted = 0;

        foreach ($specs as $spec) {
            $covered[$spec->name] = true;

            if ($budget <= 0) {
                $omitted++;

                continue;
            }

            $budget--;
            $path = [...$parentPath, $spec->name];
            $action = $actions[$this->pathKey($path)] ?? null;

            if ($action !== null) {
                $children[] = $this->sanitizedNode($path, $spec->name, $native, $action, $caps);
            } elseif (property_exists($native, $spec->name)) {
                $children[] = $this->valueNode($path, $spec->name, $native->{$spec->name}, $caps, $this->depthOf($path), $budget);
            } else {
                $children[] = $this->notSubmittedNode($path, $spec->name);
            }
        }

        foreach ($this->extraKeys($native, $covered) as $key) {
            if ($budget <= 0) {
                $omitted++;

                continue;
            }

            $budget--;
            $path = [...$parentPath, $key];
            $children[] = $this->valueNode($path, $key, $native->{$key}, $caps, $this->depthOf($path), $budget);
        }

        return [$children, $omitted];
    }

    /**
     * @param  list<string|int>  $parentPath
     * @param  array<string, string>  $actions
     * @return array{0: list<PresentationNode>, 1: int}
     */
    private function consumerChildren(array $parentPath, stdClass $native, array $actions, ResolverCaps $caps, int $depth, int &$budget): array
    {
        $children = [];
        $omitted = 0;

        foreach (get_object_vars($native) as $key => $value) {
            if ($budget <= 0) {
                $omitted++;

                continue;
            }

            $budget--;
            $path = [...$parentPath, (string) $key];
            $action = $actions[$this->pathKey($path)] ?? null;

            $children[] = $action !== null
                ? $this->sanitizedNode($path, (string) $key, $native, $action, $caps)
                : $this->valueNode($path, (string) $key, $value, $caps, $depth, $budget);
        }

        return [$children, $omitted];
    }

    /**
     * @param  list<string|int>  $path
     */
    private function sanitizedNode(array $path, string $key, stdClass $native, string $action, ResolverCaps $caps): PresentationNode
    {
        $state = SanitizationAction::classify($action);

        if ($state === FieldState::Transformed && property_exists($native, $key)) {
            return $this->scalarLeaf($path, $key, $native->{$key}, $state, $action, $caps);
        }

        return new PresentationNode(
            path: $path,
            key: $key,
            state: $state,
            value: null,
            valueType: 'null',
            action: $action,
            truncated: false,
            children: null,
            childrenOmitted: 0,
        );
    }

    /**
     * @param  list<string|int>  $path
     */
    private function notSubmittedNode(array $path, string $key): PresentationNode
    {
        return new PresentationNode(
            path: $path,
            key: $key,
            state: FieldState::NotSubmitted,
            value: null,
            valueType: 'null',
            action: null,
            truncated: false,
            children: null,
            childrenOmitted: 0,
        );
    }

    /**
     * @param  list<string|int>  $path
     */
    private function scalarNode(array $path, string $key, mixed $rawValue, ?string $action, ResolverCaps $caps): PresentationNode
    {
        if ($action !== null) {
            $state = SanitizationAction::classify($action);

            if ($state === FieldState::Transformed) {
                return $this->scalarLeaf($path, $key, $rawValue, $state, $action, $caps);
            }

            return new PresentationNode($path, $key, $state, null, 'null', $action, false, null, 0);
        }

        if ($rawValue === null) {
            return new PresentationNode($path, $key, FieldState::NotSubmitted, null, 'null', null, false, null, 0);
        }

        return $this->scalarLeaf($path, $key, $rawValue, $this->presenceState($rawValue), null, $caps);
    }

    /**
     * @param  list<string|int>  $path
     */
    private function valueNode(array $path, string $key, mixed $value, ResolverCaps $caps, int $depth, int &$budget): PresentationNode
    {
        if ($value instanceof stdClass) {
            return $this->containerNode($path, $key, 'object', get_object_vars($value), $caps, $depth, $budget);
        }

        if (is_array($value)) {
            return $this->containerNode($path, $key, 'list', $value, $caps, $depth, $budget);
        }

        return $this->scalarLeaf($path, $key, $value, $this->presenceState($value), null, $caps);
    }

    /**
     * @param  list<string|int>  $path
     * @param  array<array-key, mixed>  $entries
     */
    private function containerNode(array $path, string $key, string $valueType, array $entries, ResolverCaps $caps, int $depth, int &$budget): PresentationNode
    {
        if ($entries === []) {
            return new PresentationNode($path, $key, FieldState::Empty, null, $valueType, null, false, [], 0);
        }

        [$children, $omitted] = $this->childNodes($path, $entries, $caps, $depth, $budget);

        return new PresentationNode(
            path: $path,
            key: $key,
            state: FieldState::Present,
            value: null,
            valueType: $valueType,
            action: null,
            truncated: false,
            children: $children,
            childrenOmitted: $omitted,
        );
    }

    /**
     * @param  list<string|int>  $path
     * @param  array<array-key, mixed>  $entries
     * @return array{0: list<PresentationNode>, 1: int}
     */
    private function childNodes(array $path, array $entries, ResolverCaps $caps, int $depth, int &$budget): array
    {
        if ($depth >= $caps->maxDepth) {
            return [[], count($entries)];
        }

        $children = [];
        $seen = 0;
        $omitted = 0;

        foreach ($entries as $childKey => $childValue) {
            if ($seen >= $caps->maxChildren || $budget <= 0) {
                $omitted++;

                continue;
            }

            $seen++;
            $budget--;
            $children[] = $this->valueNode([...$path, $childKey], (string) $childKey, $childValue, $caps, $depth + 1, $budget);
        }

        return [$children, $omitted];
    }

    /**
     * @param  list<string|int>  $path
     */
    private function scalarLeaf(array $path, string $key, mixed $value, FieldState $state, ?string $action, ResolverCaps $caps): PresentationNode
    {
        [$normalized, $valueType, $truncated] = $this->normalizeScalar($value, $caps);

        return new PresentationNode(
            path: $path,
            key: $key,
            state: $state,
            value: $normalized,
            valueType: $valueType,
            action: $action,
            truncated: $truncated,
            children: null,
            childrenOmitted: 0,
        );
    }

    /**
     * @return array{0: string|int|float|bool|null, 1: string, 2: bool}
     */
    private function normalizeScalar(mixed $value, ResolverCaps $caps): array
    {
        if (is_string($value)) {
            $truncated = strlen($value) > $caps->maxValueLength;

            return [$truncated ? substr($value, 0, $caps->maxValueLength) : $value, 'string', $truncated];
        }

        if (is_int($value) || is_float($value)) {
            return [$value, 'number', false];
        }

        if (is_bool($value)) {
            return [$value, 'boolean', false];
        }

        return [null, 'null', false];
    }

    private function presenceState(mixed $value): FieldState
    {
        return $value === '' || $value === null ? FieldState::Empty : FieldState::Present;
    }

    /**
     * @param  array<string, true>  $covered
     * @return list<string>
     */
    private function extraKeys(stdClass $native, array $covered): array
    {
        $extra = [];

        foreach (array_keys(get_object_vars($native)) as $key) {
            if (! isset($covered[(string) $key])) {
                $extra[] = (string) $key;
            }
        }

        return $extra;
    }

    /**
     * @param  list<string|int>  $path
     */
    private function depthOf(array $path): int
    {
        return count($path) - 1;
    }

    /**
     * @param  list<string|int>  $path
     */
    private function pathKey(array $path): string
    {
        return implode("\0", array_map(static fn (string|int $segment): string => (string) $segment, $path));
    }
}
