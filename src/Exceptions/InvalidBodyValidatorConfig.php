<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use InvalidArgumentException;

class InvalidBodyValidatorConfig extends InvalidArgumentException
{
    public static function builtInType(string $type): self
    {
        return new self('A body_validators entry cannot override a built-in report type: '.MessageValue::escape($type));
    }

    public static function notAValidator(string $type): self
    {
        return new self('The body_validators entry must name a class implementing ReportBodyValidator: '.MessageValue::escape($type));
    }
}
