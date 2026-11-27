<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\Schema;

/**
 * One append-only row per file let out of quarantine (#7). Keyed by the scan
 * ULID, not a foreign key, so pruning old scans never takes the audit with it.
 */
return new class extends Migration
{
    public function up(): void
    {
        $this->schema()->create('content_security_releases', function (Blueprint $table): void {
            $table->id();
            $table->ulid('scan_id')->index();
            $table->string('actor_id', 64)->nullable();

            // The disposition, kept apart from the verdict: an override
            // releases a file whose rescan was not clean, and says why.
            $table->boolean('overridden');
            $table->text('reason')->nullable();
            $table->string('scan_status', 16);

            // Which bytes were released: the version the rescan read.
            $table->char('checksum_sha256', 64);
            $table->string('original_filename')->nullable();
            $table->unsignedBigInteger('file_size');

            $table->string('target_disk', 64);
            $table->string('target_path');
            $table->timestamp('created_at');
        });
    }

    public function down(): void
    {
        $this->schema()->dropIfExists('content_security_releases');
    }

    private function schema(): Builder
    {
        return Schema::connection(config('content-security.persistence.connection'));
    }
};
