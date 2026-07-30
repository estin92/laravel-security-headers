<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Headers;

enum Corp: string
{
    case SameSite = 'same-site';
    case SameOrigin = 'same-origin';
    case CrossOrigin = 'cross-origin';
}
