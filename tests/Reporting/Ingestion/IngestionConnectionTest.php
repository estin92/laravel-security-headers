<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionContext;
use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionPipeline;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

beforeEach(function () {
    $this->ingestionDatabase = tempnam(sys_get_temp_dir(), 'ingestion').'.sqlite';
    touch($this->ingestionDatabase);

    config()->set('database.connections.ingestion', [
        'driver' => 'sqlite',
        'database' => $this->ingestionDatabase,
        'prefix' => '',
        'foreign_key_constraints' => true,
    ]);
    config()->set('security-headers.reporting.ingestion.database.connection', 'ingestion');

    // A unique fingerprint makes the second report in a duplicate batch fail mid-transaction.
    Schema::connection('ingestion')->create('security_reports', function ($table) {
        $table->unsignedBigInteger('id', true);
        $table->string('type', 64);
        $table->string('protocol', 24);
        $table->text('url')->nullable();
        $table->string('url_origin', 255)->nullable();
        $table->unsignedBigInteger('age')->nullable();
        $table->text('reported_user_agent')->nullable();
        $table->text('request_user_agent')->nullable();
        $table->string('client_ip', 45)->nullable();
        $table->text('body')->nullable();
        $table->string('storage_mode', 16);
        $table->string('sanitizer_version', 80);
        $table->text('sanitization_actions');
        $table->char('incident_fingerprint', 64)->unique();
        $table->timestamp('received_at');
    });
});

afterEach(function () {
    @unlink($this->ingestionDatabase);
});

function connectionContext(): IngestionContext
{
    return new IngestionContext('203.0.113.9', 'req-UA', new DateTimeImmutable('2026-08-03T00:00:00Z'));
}

function duplicateBatch(): string
{
    $report = [
        'type' => 'csp-violation',
        'age' => 10,
        'url' => 'https://example.com/p',
        'user_agent' => 'Mozilla/5.0',
        'body' => ['blockedURL' => 'https://evil.example/x'],
    ];

    return json_encode([$report, $report], JSON_THROW_ON_ERROR);
}

test('the batch transaction runs on the configured ingestion connection, so a mid-batch failure rolls the whole batch back', function () {
    $result = app(IngestionPipeline::class)->ingest('application/reports+json', duplicateBatch(), connectionContext());

    // The duplicate fingerprint fails the second insert; a transaction on the right connection rolls the first back too.
    expect($result->status)->toBe(503);
    expect(DB::connection('ingestion')->table('security_reports')->count())->toBe(0);
});
