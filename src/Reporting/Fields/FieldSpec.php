<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Fields;

final readonly class FieldSpec
{
    /**
     * @param  list<string>  $allowed
     */
    public function __construct(
        public string $name,
        public FieldKind $kind,
        public array $allowed = [],
    ) {}
}
