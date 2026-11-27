<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Events;

use Illuminate\Foundation\Events\Dispatchable;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;

/**
 * A quarantined file was let back out. `overridden` marks a release that
 * bypassed the clean-rescan requirement — the single most audit-worthy
 * action in the package. `scanStatus` is the rescan's real verdict, and
 * `reason` the justification an override must give.
 */
final class QuarantineReleased
{
    use Dispatchable;

    public function __construct(
        public readonly ScanId $scanId,
        public readonly string $targetDisk,
        public readonly string $targetPath,
        public readonly int|string|null $actorId,
        public readonly bool $overridden = false,
        public readonly ?string $reason = null,
        public readonly ?ScanStatus $scanStatus = null,
    ) {}
}
