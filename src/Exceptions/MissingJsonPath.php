<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Support\MessageValue;
use RuntimeException;

class MissingJsonPath extends RuntimeException
{
    /**
     * @param  list<string|int>  $path
     */
    public static function at(array $path): self
    {
        return new self('No value exists at JSON path: '.MessageValue::escape(implode('.', array_map('strval', $path))));
    }
}
