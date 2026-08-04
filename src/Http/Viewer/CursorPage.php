<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Viewer;

use Estin92\SecurityHeaders\Models\SecurityReport;
use Illuminate\Support\Collection;

final readonly class CursorPage
{
    /**
     * @param  Collection<int, SecurityReport>  $items
     */
    public function __construct(
        public Collection $items,
        public ?string $nextCursor,
    ) {}
}
