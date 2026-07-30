<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Headers;

enum Coop: string
{
    case UnsafeNone = 'unsafe-none';
    case SameOriginAllowPopups = 'same-origin-allow-popups';
    case SameOrigin = 'same-origin';
    case NoopenerAllowPopups = 'noopener-allow-popups';
}
