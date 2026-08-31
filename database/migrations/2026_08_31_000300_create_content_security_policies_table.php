<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\Schema;

/**
 * Runtime policy overrides, edited from the console.
 *
 * Deliberately an *override* table, not a replacement: config remains the
 * baseline and the thing a deployment ships with. A row here says "this
 * installation has changed these fields", which keeps the two sources
 * separable — and keeps `content-security:policy --reset` meaningful.
 */
return new class extends Migration
{
    public function up(): void
    {
        $this->schema()->create('content_security_policies', function (Blueprint $table): void {
            $table->id();

            $table->string('name', 64);
            $table->string('type', 16);
            $table->string('label')->nullable();
            $table->boolean('enabled')->default(true);

            // Only the fields the operator actually changed.
            $table->json('settings');

            // Who changed it last, for the audit trail.
            $table->string('updated_by', 64)->nullable();
            $table->string('note', 500)->nullable();

            $table->timestamps();

            $table->unique(['type', 'name']);
        });
    }

    public function down(): void
    {
        $this->schema()->dropIfExists('content_security_policies');
    }

    private function schema(): Builder
    {
        return Schema::connection(config('content-security.persistence.connection'));
    }
};
