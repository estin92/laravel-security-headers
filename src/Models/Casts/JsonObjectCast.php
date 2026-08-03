<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Models\Casts;

use Estin92\SecurityHeaders\Support\JsonObject;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use JsonException;
use stdClass;

/**
 * @implements CastsAttributes<JsonObject, mixed>
 */
class JsonObjectCast implements CastsAttributes
{
    /**
     * @param  array<string, mixed>  $attributes
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): ?JsonObject
    {
        if (! is_string($value)) {
            return null;
        }

        try {
            $decoded = json_decode($value, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            Log::error('A stored security report body was not valid JSON.', [
                'model' => $model::class,
                'key' => $model->getKey(),
            ]);

            return null;
        }

        if (! $decoded instanceof stdClass) {
            return null;
        }

        return JsonObject::fromNative($decoded);
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! $value instanceof JsonObject) {
            throw new InvalidArgumentException('The body attribute must be a '.JsonObject::class.' or null.');
        }

        return $value->toJson();
    }
}
