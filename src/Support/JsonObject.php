<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Support;

use Estin92\SecurityHeaders\Exceptions\MissingJsonPath;
use stdClass;

final class JsonObject
{
    private function __construct(private readonly stdClass $value) {}

    public static function fromNative(stdClass $value): self
    {
        $copy = self::deepCopy($value);

        /** @var stdClass $copy */
        return new self($copy);
    }

    /**
     * @param  list<string|int>  $path
     */
    public function has(array $path): bool
    {
        return $this->lookup($path)['found'];
    }

    /**
     * @param  list<string|int>  $path
     *
     * @throws MissingJsonPath
     */
    public function get(array $path): mixed
    {
        $result = $this->lookup($path);

        if (! $result['found']) {
            throw MissingJsonPath::at($path);
        }

        return $this->wrap($result['value']);
    }

    /**
     * @param  list<string|int>  $path
     */
    public function getOrNull(array $path): mixed
    {
        $result = $this->lookup($path);

        return $result['found'] ? $this->wrap($result['value']) : null;
    }

    public function toNative(): stdClass
    {
        $copy = self::deepCopy($this->value);

        /** @var stdClass $copy */
        return $copy;
    }

    public function toJson(): string
    {
        return (string) json_encode($this->value, JSON_THROW_ON_ERROR);
    }

    /**
     * @param  list<string|int>  $path
     * @return array{found: bool, value: mixed}
     */
    private function lookup(array $path): array
    {
        $current = $this->value;

        foreach ($path as $segment) {
            if ($current instanceof stdClass && is_string($segment) && property_exists($current, $segment)) {
                $current = $current->{$segment};

                continue;
            }

            if (is_array($current) && is_int($segment) && array_key_exists($segment, $current)) {
                $current = $current[$segment];

                continue;
            }

            return ['found' => false, 'value' => null];
        }

        return ['found' => true, 'value' => $current];
    }

    private function wrap(mixed $value): mixed
    {
        if ($value instanceof stdClass) {
            return self::fromNative($value);
        }

        if (is_array($value)) {
            return self::deepCopy($value);
        }

        return $value;
    }

    private static function deepCopy(mixed $value): mixed
    {
        if ($value instanceof stdClass) {
            $copy = new stdClass;

            foreach (get_object_vars($value) as $key => $item) {
                $copy->{$key} = self::deepCopy($item);
            }

            return $copy;
        }

        if (is_array($value)) {
            return array_map(fn (mixed $item): mixed => self::deepCopy($item), $value);
        }

        return $value;
    }
}
