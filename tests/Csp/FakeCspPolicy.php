<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Tests\Csp;

use Closure;
use Estin92\SecurityHeaders\Csp\CspPolicy;
use Estin92\SecurityHeaders\Csp\Keyword;

class FakeCspPolicy extends CspPolicy
{
    public function __construct(private Closure $define) {}

    protected function define(): void
    {
        Closure::bind($this->define, $this, CspPolicy::class)();
    }

    public function declareOutsideDefinition(string $name, Keyword|string ...$sources): void
    {
        $this->directive($name, ...$sources);
    }
}
