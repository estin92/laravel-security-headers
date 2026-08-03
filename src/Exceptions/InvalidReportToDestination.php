<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;

class InvalidReportToDestination extends InvalidArgumentException
{
    public static function noTarget(): self
    {
        return new self('A reporting directive needs at least one target: a modern endpoint or a legacy group.');
    }

    public static function removalGroupNotAddressable(string $group): self
    {
        return new self('A Report-To group with max_age 0 (removal) cannot be used as a reporting target: '.MessageValue::escape($group));
    }

    public static function targetNameMismatch(string $modern, string $legacy): self
    {
        return new self('A channel\'s modern endpoint ('.MessageValue::escape($modern).') and legacy group ('.MessageValue::escape($legacy).') must share one name for a single report-to directive.');
    }
}
