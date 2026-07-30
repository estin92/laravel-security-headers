<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Headers;

enum XFrameOptions: string
{
    case Deny = 'DENY';
    case SameOrigin = 'SAMEORIGIN';
}
