<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Viewer;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Gate;

final class ViewerGate
{
    public const ABILITY = 'viewSecurityHeaderReports';

    public static function allows(?Authenticatable $user): bool
    {
        if (Gate::has(self::ABILITY)) {
            return Gate::forUser($user)->allows(self::ABILITY);
        }

        return app()->environment('local');
    }
}
