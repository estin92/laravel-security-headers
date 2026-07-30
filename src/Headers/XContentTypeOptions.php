<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Headers;

enum XContentTypeOptions: string
{
    case NoSniff = 'nosniff';
}
