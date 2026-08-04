<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Presentation;

final class SanitizationAction
{
    private const TRANSFORMED = ['strip_query', 'mask_client_ip'];

    private const REMOVED = [
        'remove_client_ip',
        'remove_sample',
        'remove_nel_headers',
        'remove_request_user_agent',
        'remove_reported_user_agent',
    ];

    public static function classify(string $action): FieldState
    {
        if (in_array($action, self::TRANSFORMED, true)) {
            return FieldState::Transformed;
        }

        if (in_array($action, self::REMOVED, true)) {
            return FieldState::Removed;
        }

        // A future/unknown action — including a `remove_`-prefixed one the package
        // does not recognise — is never guessed as removed or transformed.
        return FieldState::UnknownAction;
    }
}
