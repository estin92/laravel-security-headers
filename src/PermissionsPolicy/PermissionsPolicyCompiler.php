<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\PermissionsPolicy;

use Estin92\SecurityHeaders\Exceptions\InvalidPermissionsPolicy;

class PermissionsPolicyCompiler
{
    /**
     * @param  array<mixed>  $features  Unvalidated config; feature names and origins are guarded here.
     */
    public function compile(array $features): ?string
    {
        if ($features === []) {
            return null;
        }

        $parts = [];

        foreach ($features as $feature => $allowlist) {
            $this->guardFeatureName($feature);

            $parts[] = "{$feature}={$this->allowlist($feature, is_array($allowlist) ? $allowlist : [])}";
        }

        return implode(', ', $parts);
    }

    /**
     * @param  array<mixed>  $allowlist
     */
    private function allowlist(string $feature, array $allowlist): string
    {
        if ($allowlist === [Keyword::Any]) {
            return '*';
        }

        if (in_array(Keyword::Any, $allowlist, true)) {
            throw InvalidPermissionsPolicy::wildcardMustBeAlone($feature);
        }

        $items = array_map(
            fn (mixed $item): string => $item instanceof Keyword
                ? $item->value
                : '"'.$this->guardOrigin(is_string($item) ? $item : '').'"',
            $allowlist,
        );

        return '('.implode(' ', $items).')';
    }

    private function guardFeatureName(int|string $feature): void
    {
        if (! is_string($feature) || preg_match('/\A[a-z][a-z0-9-]*\z/', $feature) !== 1) {
            throw InvalidPermissionsPolicy::invalidFeature((string) $feature);
        }
    }

    private function guardOrigin(string $origin): string
    {
        if ($origin === '' || preg_match('/[\s;,"]/', $origin) === 1) {
            throw InvalidPermissionsPolicy::invalidOrigin($origin);
        }

        if (Keyword::tryFrom($origin) !== null) {
            throw InvalidPermissionsPolicy::keywordMustUseEnum($origin);
        }

        return $origin;
    }
}
