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
        $this->schema()->create('content_security_threats', function (Blueprint $table): void {
            $table->id();

            $table->foreignId('scan_id')
                ->constrained('content_security_scans')
                ->cascadeOnDelete();

            // The signature or rule name. Indexed with the timestamp because
            // the threats page aggregates by name over a window.
            $table->string('name', 191);
            $table->string('source', 64);
            $table->string('level', 16);
            $table->text('description')->nullable();
            $table->json('metadata')->nullable();

            $table->timestamp('created_at')->nullable();

            $table->index(['name', 'created_at']);
            $table->index(['level', 'created_at']);
        });
    }

    public function down(): void
    {
        $this->schema()->dropIfExists('content_security_threats');
    }

    private function schema(): Builder
    {
        return Schema::connection(config('content-security.persistence.connection'));
    }
};
