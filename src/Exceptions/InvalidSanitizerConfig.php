<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use InvalidArgumentException;

class InvalidSanitizerConfig extends InvalidArgumentException
{
    public static function removeAndMaskConflict(): self
    {
        return new self('remove_client_ip and mask_client_ip cannot both be enabled — they are mutually exclusive dispositions of one field.');
    }

    public static function exactIpInSanitizedMode(): self
    {
        return new self('Sanitized mode cannot keep an exact client IP: enable remove_client_ip or mask_client_ip, or switch to raw mode.');
    }
}
