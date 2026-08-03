<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use InvalidArgumentException;

// The message can be logged, so never put the report body in it.
class InvalidReportBody extends InvalidArgumentException
{
    public static function forType(string $type): self
    {
        return new self('Report body failed validation for type: '.$type);
    }
}
