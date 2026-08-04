<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Presentation;

final readonly class ResolverCaps
{
    /**
     * @param  int  $maxNodes  Bounds the expandable body subtree only. The four context
     *                         fields and the body node itself form a fixed skeleton that
     *                         is always emitted, so the total node count is $maxNodes + 5.
     */
    public function __construct(
        public int $maxDepth = 12,
        public int $maxChildren = 200,
        public int $maxNodes = 2000,
        public int $maxValueLength = 4096,
    ) {}
}
