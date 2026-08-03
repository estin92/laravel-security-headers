<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Reporting\Ingestion\IngestionStorage;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::connection(IngestionStorage::connection())->create(IngestionStorage::table(), function (Blueprint $table) {
            $table->unsignedBigInteger('id', true);
            $table->string('type', 64)->index();
            $table->string('protocol', 24)->index();
            $table->text('url')->nullable();
            $table->string('url_origin', 255)->nullable()->index();
            $table->unsignedBigInteger('age')->nullable();
            $table->text('reported_user_agent')->nullable();
            $table->text('request_user_agent')->nullable();
            $table->string('client_ip', 45)->nullable();
            // On engines without a native JSON type this becomes LONGTEXT
            $table->json('body')->nullable();
            $table->string('storage_mode', 16);
            $table->string('sanitizer_version', 80);
            $table->json('sanitization_actions');
            $table->char('incident_fingerprint', 64)->index();
            $table->timestamp('received_at');

            $table->index(['received_at', 'id']);
        });
    }

    public function down(): void
    {
        Schema::connection(IngestionStorage::connection())->dropIfExists(IngestionStorage::table());
    }
};
