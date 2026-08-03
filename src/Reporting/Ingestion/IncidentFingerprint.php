<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use BackedEnum;
use Estin92\SecurityHeaders\Support\JsonObject;
use stdClass;

final class IncidentFingerprint
{
    public static function for(
        ReportTypeContract&BackedEnum $type,
        ReportProtocol $protocol,
        ?string $url,
        ?JsonObject $body,
        StorageMode $storageMode,
        string $sanitizerVersion,
    ): string {
        $canonical = [
            'type' => $type->value,
            'protocol' => $protocol->value,
            'url' => $url,
            'body' => self::canonicalizeBody($body),
            'storage_mode' => $storageMode->value,
            'sanitizer_version' => $sanitizerVersion,
        ];

        return hash('sha256', (string) json_encode($canonical, JSON_THROW_ON_ERROR));
    }

    /**
     * @return array{present: bool, value?: mixed}
     */
    private static function canonicalizeBody(?JsonObject $body): array
    {
        if ($body === null) {
            return ['present' => false];
        }

        return ['present' => true, 'value' => self::canonicalize($body->toNative())];
    }

    private static function canonicalize(mixed $value): mixed
    {
        if ($value instanceof stdClass) {
            $entries = [];

            foreach (get_object_vars($value) as $key => $item) {
                $entries[] = [$key, self::canonicalize($item)];
            }

            usort($entries, fn (array $a, array $b): int => $a[0] <=> $b[0]);

            // The 'object' and 'list' labels keep an empty object and an empty list apart.
            return ['object', $entries];
        }

        if (is_array($value)) {
            return ['list', array_map(self::canonicalize(...), $value)];
        }

        return $value;
    }
}
