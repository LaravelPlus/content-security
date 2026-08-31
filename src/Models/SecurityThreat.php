<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * @property int $id
 * @property int $scan_id
 * @property string $name
 * @property string $source
 * @property ThreatLevel $level
 * @property string|null $description
 * @property array<string, mixed>|null $metadata
 * @property Carbon|null $created_at
 * @property-read SecurityScan $scan
 */
final class SecurityThreat extends Model
{
    public const UPDATED_AT = null;

    protected $table = 'content_security_threats';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'level' => ThreatLevel::class,
            'metadata' => 'array',
            'created_at' => 'datetime',
        ];
    }

    public function getConnectionName(): ?string
    {
        /** @var string|null $connection */
        $connection = config('content-security.persistence.connection');

        return $connection ?? parent::getConnectionName();
    }

    /**
     * @return BelongsTo<SecurityScan, $this>
     */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(SecurityScan::class, 'scan_id');
    }
}
