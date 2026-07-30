<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Headers;

enum XssProtection: string
{
    case Disabled = '0';
    case Enabled = '1';
    case Block = '1; mode=block';
}
