<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Csp;

use Estin92\SecurityHeaders\Exceptions\InvalidCspDirective;

class CspCompiler
{
    public function compile(CspPolicy $policy, ?string $nonce): string
    {
        if ($policy->requiresNonce() && $nonce === null) {
            throw InvalidCspDirective::missingNonce();
        }

        if ($policy->directives() === []) {
            throw InvalidCspDirective::emptyPolicy();
        }

        $parts = [];

        foreach ($policy->directives() as $name => $sources) {
            $this->guardDirectiveName($name);

            foreach ($sources as $source) {
                $this->guardAgainstSourceInjection($source);
            }

            if ($nonce !== null && $policy->directiveIsNonced($name)) {
                $sources[] = "'nonce-{$this->guardNonce($nonce)}'";
            }

            $parts[] = trim($name.' '.implode(' ', $sources));
        }

        return implode('; ', $parts);
    }

    private function guardDirectiveName(string $name): void
    {
        if (preg_match('/\A[a-z][a-z0-9-]*\z/', $name) !== 1) {
            throw InvalidCspDirective::invalidName($name);
        }
    }

    private function guardAgainstSourceInjection(string $source): void
    {
        if ($source === '' || preg_match('/[\s;,]/', $source) === 1) {
            throw InvalidCspDirective::invalidSource($source);
        }
    }

    private function guardNonce(string $nonce): string
    {
        if (preg_match('/\A[A-Za-z0-9+\/_-]+={0,2}\z/', $nonce) !== 1) {
            throw InvalidCspDirective::invalidNonce();
        }

        return $nonce;
    }
}
