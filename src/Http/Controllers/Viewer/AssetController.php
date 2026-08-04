<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Controllers\Viewer;

use Estin92\SecurityHeaders\Http\Viewer\ViewerAssets;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\BinaryFileResponse;

final class AssetController
{
    private const CONTENT_TYPES = [
        'js' => 'text/javascript',
        'css' => 'text/css',
        'svg' => 'image/svg+xml',
        'woff2' => 'font/woff2',
    ];

    public function __construct(private readonly ViewerAssets $assets) {}

    public function __invoke(string $path): Response|BinaryFileResponse
    {
        if (! $this->assets->isServable($path)) {
            return new Response('', 404);
        }

        $extension = pathinfo($path, PATHINFO_EXTENSION);
        $contentType = self::CONTENT_TYPES[$extension] ?? null;

        if ($contentType === null) {
            return new Response('', 404);
        }

        $file = $this->assets->distPath().'/'.$path;

        if (! is_file($file)) {
            return new Response('', 404);
        }

        return new BinaryFileResponse($file, 200, [
            'Content-Type' => $contentType,
            'X-Content-Type-Options' => 'nosniff',
            'Cache-Control' => 'public, max-age=31536000, immutable',
        ]);
    }
}
