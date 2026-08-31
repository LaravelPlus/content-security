<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanType;

/**
 * The audit row for one scan.
 *
 * Reached through ScanRepository from the pipeline — the model is the
 * console's read model and the repository's storage detail, not something
 * domain services talk to.
 *
 * @property int $id
 * @property string $scan_id
 * @property ScanType $type
 * @property ScanStatus $status
 * @property string|null $scanner
 * @property string|null $policy
 * @property string|null $original_filename
 * @property string|null $extension
 * @property string|null $declared_mime
 * @property string|null $detected_mime
 * @property int|null $file_size
 * @property string|null $checksum_sha256
 * @property int|null $content_length
 * @property string|null $content_sample
 * @property int $duration_ms
 * @property int $threat_count
 * @property string|null $quarantine_disk
 * @property string|null $quarantine_path
 * @property string|null $request_id
 * @property string|null $user_id
 * @property array<string, mixed>|null $metadata
 * @property Carbon|null $started_at
 * @property Carbon|null $completed_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 * @property-read Collection<int, SecurityThreat> $threats
 */
final class SecurityScan extends Model
{
    protected $table = 'content_security_scans';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'type' => ScanType::class,
            'status' => ScanStatus::class,
            'metadata' => 'array',
            'file_size' => 'integer',
            'content_length' => 'integer',
            'duration_ms' => 'integer',
            'threat_count' => 'integer',
            'started_at' => 'datetime',
            'completed_at' => 'datetime',
        ];
    }

    public function getConnectionName(): ?string
    {
        /** @var string|null $connection */
        $connection = config('content-security.persistence.connection');

        return $connection ?? parent::getConnectionName();
    }

    public function getRouteKeyName(): string
    {
        return 'scan_id';
    }

    /**
     * @return HasMany<SecurityThreat, $this>
     */
    public function threats(): HasMany
    {
        return $this->hasMany(SecurityThreat::class, 'scan_id');
    }

    /**
     * @param  Builder<SecurityScan>  $query
     * @return Builder<SecurityScan>
     */
    public function scopeQuarantined(Builder $query): Builder
    {
        return $query->where('status', ScanStatus::Quarantined->value)
            ->whereNotNull('quarantine_path');
    }

    /**
     * @param  Builder<SecurityScan>  $query
     * @return Builder<SecurityScan>
     */
    public function scopeSince(Builder $query, int $hours): Builder
    {
        return $query->where('created_at', '>=', now()->subHours($hours));
    }

    public function isQuarantined(): bool
    {
        return $this->quarantine_path !== null && $this->quarantine_disk !== null;
    }
}
