<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\PermissionsPolicy;

enum Allow: string
{
    case Self = 'self';
    case Any = '*';
}
