<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Presentation;

final readonly class ResolverCaps
{
    public function __construct(
        public int $maxDepth = 12,
        public int $maxChildren = 200,
        public int $maxNodes = 2000,
        public int $maxValueLength = 4096,
    ) {}
}
