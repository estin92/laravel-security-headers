<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Controllers\Viewer;

use Estin92\SecurityHeaders\Http\Viewer\ViewerAssets;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\View as ViewFactory;

final class ShellController
{
    private const BUILD_MISSING_MESSAGE = 'The security-headers report viewer assets are missing. Run its build (npm ci && npm run build) and deploy the dist directory.';

    public function __construct(private readonly ViewerAssets $assets) {}

    public function __invoke(): View|Response
    {
        $script = $this->assets->entryScript();

        if ($script === null) {
            Log::error(self::BUILD_MISSING_MESSAGE);

            return new Response($this->unavailableBody(), 500);
        }

        $style = $this->assets->entryStyle();

        return ViewFactory::make('security-headers::viewer.shell', [
            'scriptSrc' => $this->assets->url($script),
            'styleSrc' => $style !== null ? $this->assets->url($style) : null,
        ]);
    }

    private function unavailableBody(): string
    {
        if (app()->environment('local')) {
            return '<!doctype html><title>Report viewer unavailable</title>'
                .'<p>'.e(self::BUILD_MISSING_MESSAGE).'</p>';
        }

        return '<!doctype html><title>Unavailable</title><p>This page is temporarily unavailable.</p>';
    }
}
