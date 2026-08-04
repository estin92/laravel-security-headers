<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Presentation;

enum FieldState: string
{
    case Present = 'present';
    case Empty = 'empty';
    case Transformed = 'transformed';
    case Removed = 'removed';
    case UnknownAction = 'unknown_action';
    case NotSubmitted = 'not_submitted';
}
