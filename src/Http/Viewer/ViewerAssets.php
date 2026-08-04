<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Viewer;

use JsonException;

final class ViewerAssets
{
    private const ENTRY = 'resources/js/app.ts';

    /**
     * @var array<string, mixed>|null
     */
    private ?array $manifest = null;

    private bool $loaded = false;

    public function distPath(): string
    {
        $override = config('security-headers.reporting.viewer.dist_path');

        return is_string($override) ? $override : dirname(__DIR__, 3).'/dist';
    }

    public function built(): bool
    {
        return $this->entryScript() !== null;
    }

    public function entryScript(): ?string
    {
        $file = $this->entry(self::ENTRY)['file'] ?? null;

        return is_string($file) ? $file : null;
    }

    public function entryStyle(): ?string
    {
        $css = $this->entry(self::ENTRY)['css'] ?? null;

        if (is_array($css) && isset($css[0]) && is_string($css[0])) {
            return $css[0];
        }

        return null;
    }

    public function url(string $file): string
    {
        $path = config('security-headers.reporting.viewer.path', '/security-headers/reports');

        return rtrim(is_string($path) ? $path : '/security-headers/reports', '/').'/assets/'.$file;
    }

    public function isServable(string $file): bool
    {
        foreach (array_keys($this->manifest()) as $key) {
            $entry = $this->entry($key);

            if (($entry['file'] ?? null) === $file) {
                return true;
            }

            $css = $entry['css'] ?? [];

            if (is_array($css) && in_array($file, $css, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function entry(string $name): array
    {
        $entry = $this->manifest()[$name] ?? null;

        return is_array($entry) ? $entry : [];
    }

    /**
     * @return array<string, mixed>
     */
    private function manifest(): array
    {
        if ($this->loaded) {
            return $this->manifest ?? [];
        }

        $this->loaded = true;
        $path = $this->distPath().'/.vite/manifest.json';

        if (! is_file($path)) {
            return $this->manifest = [];
        }

        $raw = (string) file_get_contents($path);

        try {
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $this->manifest = [];
        }

        if (! is_array($decoded)) {
            return $this->manifest = [];
        }

        $manifest = [];

        foreach ($decoded as $key => $value) {
            $manifest[(string) $key] = $value;
        }

        return $this->manifest = $manifest;
    }
}
