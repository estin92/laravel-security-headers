<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Viewer;

final class ViewerRoutes
{
    public const PREFIX = 'security-headers.viewer';

    public const SHELL = self::PREFIX.'.shell';

    public const ASSETS = self::PREFIX.'.assets';

    public const API_REPORTS = self::PREFIX.'.api.reports';

    public const API_REPORT = self::PREFIX.'.api.report';

    public const API_INCIDENTS = self::PREFIX.'.api.incidents';

    public const API_FILTERS = self::PREFIX.'.api.filters';

    public const WILDCARD = self::PREFIX.'.*';

    public const API_WILDCARD = self::PREFIX.'.api.*';
}
