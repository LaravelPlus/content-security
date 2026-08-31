<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Models\SecurityScan;

/**
 * The audit trail. Kept behind a contract so a host can point it at another
 * store — or at a no-op — without the pipeline knowing.
 */
interface ScanRepository
{
    /** Records a scan as started. Idempotent on the scan id. */
    public function start(ScanContext $context, ?FileReference $file = null): void;

    public function markScanning(ScanId $id): void;

    public function complete(ScanResult $result): void;

    public function markStatus(ScanId $id, ScanStatus $status): void;

    /** @param array<string, mixed> $attributes */
    public function recordQuarantine(ScanId $id, array $attributes): void;

    public function find(ScanId $id): ?SecurityScan;

    /**
     * Aggregate counters for the dashboard.
     *
     * @return array<string, int|float>
     */
    public function statistics(int $sinceHours = 24): array;

    /** Removes scan rows older than the retention window. Returns rows deleted. */
    public function prune(int $olderThanDays): int;
}
