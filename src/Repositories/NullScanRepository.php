<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Repositories;

use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Models\SecurityScan;

/**
 * Used when `persistence.enabled` is off. Scanning still works; nothing is
 * written, and the admin console has nothing to show.
 */
final class NullScanRepository implements ScanRepository
{
    public function start(ScanContext $context, ?FileReference $file = null): void {}

    public function markScanning(ScanId $id): void {}

    public function complete(ScanResult $result): void {}

    public function markStatus(ScanId $id, ScanStatus $status): void {}

    /** @param array<string, mixed> $attributes */
    public function recordQuarantine(ScanId $id, array $attributes): void {}

    public function find(ScanId $id): ?SecurityScan
    {
        return null;
    }

    /**
     * @return array<string, int|float>
     */
    public function statistics(int $sinceHours = 24): array
    {
        return [
            'total' => 0,
            'window_hours' => $sinceHours,
            'window_total' => 0,
            'clean' => 0,
            'suspicious' => 0,
            'infected' => 0,
            'failed' => 0,
            'quarantined' => 0,
            'pending' => 0,
            'avg_duration_ms' => 0.0,
            'threats' => 0,
        ];
    }

    public function prune(int $olderThanDays): int
    {
        return 0;
    }
}
