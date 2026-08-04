<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Http\Viewer;

use Estin92\SecurityHeaders\Models\SecurityReport;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use JsonException;
use Throwable;

final class CursorCodec
{
    /**
     * Fetch one keyset page from a (received_at DESC, id DESC) query, applying the
     * incoming cursor and emitting the next one when more rows remain.
     *
     * @param  Builder<SecurityReport>  $query
     */
    public static function paginate(Builder $query, int $limit, mixed $cursor): CursorPage
    {
        self::applyKeyset($query, $cursor);

        $rows = $query->limit($limit + 1)->get();
        $page = $rows->take($limit);
        $last = $page->last();

        return new CursorPage(
            $page->values(),
            $rows->count() > $limit && $last !== null ? self::encode($last->received_at, $last->id) : null,
        );
    }

    /**
     * Narrow a (received_at DESC, id DESC) keyset query to the rows after the cursor.
     *
     * @param  Builder<SecurityReport>  $query
     */
    public static function applyKeyset(Builder $query, mixed $cursor): void
    {
        if (! is_string($cursor) || $cursor === '') {
            return;
        }

        $decoded = self::decode($cursor);

        $query->whereRaw(
            '(received_at, id) < (?, ?)',
            [$decoded['received_at']->toDateTimeString(), $decoded['id']],
        );
    }

    public static function encode(Carbon $receivedAt, int $id): string
    {
        $payload = json_encode([
            'received_at' => $receivedAt->utc()->toIso8601ZuluString(),
            'id' => $id,
        ], JSON_THROW_ON_ERROR);

        return rtrim(strtr(base64_encode($payload), '+/', '-_'), '=');
    }

    /**
     * @return array{received_at: Carbon, id: int}
     */
    public static function decode(string $cursor): array
    {
        $decoded = base64_decode(strtr($cursor, '-_', '+/'), true);

        if ($decoded === false || $decoded === '') {
            throw ViewerApiException::invalidCursor();
        }

        try {
            $payload = json_decode($decoded, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw ViewerApiException::invalidCursor();
        }

        if (! is_array($payload) || ! isset($payload['received_at'], $payload['id'])) {
            throw ViewerApiException::invalidCursor();
        }

        $id = $payload['id'];
        $rawReceivedAt = $payload['received_at'];

        if (! is_int($id) || $id < 0 || ! is_string($rawReceivedAt)) {
            throw ViewerApiException::invalidCursor();
        }

        try {
            $receivedAt = Carbon::parse($rawReceivedAt)->utc();
        } catch (Throwable) {
            throw ViewerApiException::invalidCursor();
        }

        return ['received_at' => $receivedAt, 'id' => $id];
    }
}
