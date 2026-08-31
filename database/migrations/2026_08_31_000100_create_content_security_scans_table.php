<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $this->schema()->create('content_security_scans', function (Blueprint $table): void {
            $table->id();

            // The ULID the pipeline generated. Every log line, event and
            // queue job carries it, so it is the join key across systems.
            $table->ulid('scan_id')->unique();

            $table->string('type', 16);
            $table->string('status', 16);
            $table->string('scanner', 64)->nullable();
            $table->string('policy', 64)->nullable();

            // File scans. Null for text.
            $table->string('original_filename')->nullable();
            $table->string('extension', 32)->nullable();
            $table->string('declared_mime', 191)->nullable();
            $table->string('detected_mime', 191)->nullable();
            $table->unsignedBigInteger('file_size')->nullable();

            // SHA-256 of the file, or of the text for text scans. 64 hex
            // characters — the column is sized exactly, and indexed because
            // "have we seen this before" is the question the console asks.
            $table->char('checksum_sha256', 64)->nullable();

            $table->unsignedInteger('content_length')->nullable();

            // Off by default. See config('content-security.persistence').
            $table->text('content_sample')->nullable();

            $table->unsignedInteger('duration_ms')->default(0);
            $table->unsignedSmallInteger('threat_count')->default(0);

            // Where a quarantined file went. Never shown in the console
            // unless admin.expose_paths is on.
            $table->string('quarantine_disk', 64)->nullable();
            $table->string('quarantine_path')->nullable();

            $table->string('request_id', 64)->nullable();
            $table->string('user_id', 64)->nullable();

            $table->json('metadata')->nullable();

            $table->timestamp('started_at')->nullable();
            $table->timestamp('completed_at')->nullable();
            $table->timestamps();

            // The console's default view is "recent scans, filtered by
            // status", and pruning walks created_at. One composite index
            // serves both; separate single-column ones would not.
            $table->index(['status', 'created_at']);
            $table->index(['type', 'created_at']);
            $table->index('checksum_sha256');
            $table->index('created_at');
        });
    }

    public function down(): void
    {
        $this->schema()->dropIfExists('content_security_scans');
    }

    private function schema(): Builder
    {
        return Schema::connection(config('content-security.persistence.connection'));
    }
};
