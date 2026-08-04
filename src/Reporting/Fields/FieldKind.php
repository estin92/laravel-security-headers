<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Fields;

enum FieldKind: string
{
    case StringValue = 'string';
    case NonNegativeInt = 'non_negative_int';
    case Fraction = 'fraction';
    case EnumSet = 'enum_set';
    case HeaderMap = 'header_map';
}
