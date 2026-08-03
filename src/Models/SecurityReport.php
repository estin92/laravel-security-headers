<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Models;

use DateTimeInterface;
use Estin92\SecurityHeaders\Models\Casts\JsonObjectCast;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionStorage;
use Estin92\SecurityHeaders\Support\JsonObject;
use Illuminate\Database\Eloquent\Model;

/**
 * @property int $id
 * @property string $type
 * @property string $protocol
 * @property ?string $url
 * @property ?string $url_origin
 * @property ?int $age
 * @property ?string $reported_user_agent
 * @property ?string $request_user_agent
 * @property ?string $client_ip
 * @property ?JsonObject $body
 * @property string $storage_mode
 * @property string $sanitizer_version
 * @property list<array{path: list<string|int>, action: string}> $sanitization_actions
 * @property string $incident_fingerprint
 * @property DateTimeInterface $received_at
 */
class SecurityReport extends Model
{
    public $timestamps = false;

    /**
     * @var list<string>
     */
    protected $fillable = [
        'type',
        'protocol',
        'url',
        'url_origin',
        'age',
        'reported_user_agent',
        'request_user_agent',
        'client_ip',
        'body',
        'storage_mode',
        'sanitizer_version',
        'sanitization_actions',
        'incident_fingerprint',
        'received_at',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'body' => JsonObjectCast::class,
            'sanitization_actions' => 'array',
            'age' => 'integer',
            'received_at' => 'datetime',
        ];
    }

    public function getTable(): string
    {
        return IngestionStorage::table();
    }

    public function getConnectionName(): ?string
    {
        return IngestionStorage::connection();
    }
}
