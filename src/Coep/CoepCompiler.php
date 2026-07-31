<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Coep;

use Estin92\SecurityHeaders\Exceptions\InvalidCoep;
use Estin92\SecurityHeaders\Exceptions\InvalidHeaderValue;
use Estin92\SecurityHeaders\Headers\Coep;
use Estin92\SecurityHeaders\Reporting\ReportingEndpoint;

class CoepCompiler
{
    public function compile(mixed $value, ?ReportingEndpoint $endpoint = null): string
    {
        $coep = is_string($value) ? Coep::tryFrom($value) : null;

        if ($coep === null) {
            throw InvalidHeaderValue::notInValueSet('Cross-Origin-Embedder-Policy', is_string($value) ? $value : '');
        }

        if ($coep === Coep::UnsafeNone && $endpoint !== null) {
            throw InvalidCoep::unsafeNoneWithReporting();
        }

        if ($endpoint === null) {
            return $coep->value;
        }

        return "{$coep->value}; report-to=\"{$endpoint->name}\"";
    }
}
