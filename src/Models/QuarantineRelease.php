<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LogicException;

/**
 * The audit record of one release from quarantine (#7). Written once, never
 * updated or deleted through the model.
 *
 * @property int $id
 * @property string $scan_id
 * @property string|null $actor_id
 * @property bool $overridden
 * @property string|null $reason
 * @property ScanStatus $scan_status
 * @property string $checksum_sha256
 * @property string|null $original_filename
 * @property int $file_size
 * @property string $target_disk
 * @property string $target_path
 * @property Carbon $created_at
 */
final class QuarantineRelease extends Model
{
    public const UPDATED_AT = null;

    protected $table = 'content_security_releases';

    protected $guarded = [];

    protected static function booted(): void
    {
        $immutable = static fn (): never => throw new LogicException('A quarantine release record is immutable.');

        self::updating($immutable);
        self::deleting($immutable);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'overridden' => 'boolean',
            'scan_status' => ScanStatus::class,
            'file_size' => 'integer',
        ];
    }

    public function getConnectionName(): ?string
    {
        /** @var string|null $connection */
        $connection = config('content-security.persistence.connection');

        return $connection ?? parent::getConnectionName();
    }
}
