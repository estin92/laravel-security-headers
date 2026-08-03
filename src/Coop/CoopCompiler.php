<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Coop;

use Estin92\SecurityHeaders\Exceptions\InvalidCoop;
use Estin92\SecurityHeaders\Exceptions\InvalidHeaderValue;
use Estin92\SecurityHeaders\Headers\Coop;
use Estin92\SecurityHeaders\Reporting\ReportToDestination;

class CoopCompiler
{
    public function compileEnforce(mixed $value, ?ReportToDestination $reporting): string
    {
        return $this->compile($this->coop($value), $reporting);
    }

    public function compileReportOnly(mixed $value, ReportToDestination $reporting): string
    {
        $coop = $this->coop($value);

        if ($coop === Coop::NoopenerAllowPopups) {
            throw InvalidCoop::notReportOnlyValue($coop->value);
        }

        return $this->compile($coop, $reporting);
    }

    private function coop(mixed $value): Coop
    {
        $coop = is_string($value) ? Coop::tryFrom($value) : null;

        if ($coop === null) {
            throw InvalidHeaderValue::notInValueSet('Cross-Origin-Opener-Policy', is_string($value) ? $value : '');
        }

        return $coop;
    }

    private function compile(Coop $coop, ?ReportToDestination $reporting): string
    {
        if ($reporting === null) {
            return $coop->value;
        }

        return "{$coop->value}; report-to=\"{$reporting->reportTo}\"";
    }
}
