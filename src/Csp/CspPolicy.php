<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Csp;

use Estin92\SecurityHeaders\Exceptions\InvalidCspDirective;
use LogicException;
use Throwable;

abstract class CspPolicy
{
    /**
     * @var array<string, list<string>>|null
     */
    private ?array $directives = null;

    /**
     * @var array<string, true>
     */
    private array $nonced = [];

    private bool $defined = false;

    private bool $defining = false;

    abstract protected function define(): void;

    final protected function directive(string $name, string ...$sources): void
    {
        $this->record($name, $sources);
    }

    final protected function directiveWithNonce(string $name, string ...$sources): void
    {
        $this->record($name, $sources);
        $this->nonced[$name] = true;
    }

    /**
     * @return array<string, list<string>>
     */
    public function directives(): array
    {
        $this->ensureDefined();

        return $this->directives ?? [];
    }

    public function directiveIsNonced(string $name): bool
    {
        $this->ensureDefined();

        return isset($this->nonced[$name]);
    }

    public function requiresNonce(): bool
    {
        $this->ensureDefined();

        return $this->nonced !== [];
    }

    /**
     * @param  array<string>  $sources
     */
    private function record(string $name, array $sources): void
    {
        if ($this->defined) {
            throw new LogicException('A CSP policy cannot be modified after it has been defined.');
        }

        $existing = $this->directives[$name] ?? [];

        $this->directives[$name] = array_values(array_unique([...$existing, ...$sources]));
    }

    private function ensureDefined(): void
    {
        if ($this->defined) {
            return;
        }

        if ($this->defining) {
            throw new LogicException('CSP policy definition is recursive.');
        }

        $this->defining = true;
        $this->directives = [];
        $this->nonced = [];

        try {
            $this->define();
            $this->guardDirectives();
            $this->defined = true;
        } catch (Throwable $exception) {
            $this->directives = null;
            $this->nonced = [];

            throw $exception;
        } finally {
            $this->defining = false;
        }
    }

    private function guardDirectives(): void
    {
        foreach ($this->directives ?? [] as $name => $sources) {
            if (count($sources) > 1 && in_array("'none'", $sources, true)) {
                throw InvalidCspDirective::conflictingNone($name);
            }

            if ($sources === [] && isset($this->nonced[$name])) {
                throw InvalidCspDirective::sourcesOnValuelessDirective($name);
            }
        }
    }
}
