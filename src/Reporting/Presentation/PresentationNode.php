<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Presentation;

final readonly class PresentationNode
{
    /**
     * @param  list<string|int>  $path
     * @param  list<PresentationNode>|null  $children
     */
    public function __construct(
        public array $path,
        public string $key,
        public FieldState $state,
        public string|int|float|bool|null $value,
        public string $valueType,
        public ?string $action,
        public bool $truncated,
        public ?array $children,
        public int $childrenOmitted,
    ) {}

    /**
     * @return array{
     *     path: list<string|int>,
     *     key: string,
     *     state: string,
     *     value: string|int|float|bool|null,
     *     value_type: string,
     *     action: ?string,
     *     truncated: bool,
     *     children: ?list<mixed>,
     *     children_omitted: int
     * }
     */
    public function toArray(): array
    {
        return [
            'path' => $this->path,
            'key' => $this->key,
            'state' => $this->state->value,
            'value' => $this->value,
            'value_type' => $this->valueType,
            'action' => $this->action,
            'truncated' => $this->truncated,
            'children' => $this->children === null
                ? null
                : array_map(fn (PresentationNode $child): array => $child->toArray(), $this->children),
            'children_omitted' => $this->childrenOmitted,
        ];
    }
}
