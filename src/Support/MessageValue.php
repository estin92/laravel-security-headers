<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Support;

class MessageValue
{
    public static function escape(string $value): string
    {
        return (string) json_encode($value);
    }
}
