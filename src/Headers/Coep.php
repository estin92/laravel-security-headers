<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Headers;

enum Coep: string
{
    case UnsafeNone = 'unsafe-none';
    case RequireCorp = 'require-corp';
    case Credentialless = 'credentialless';
}
