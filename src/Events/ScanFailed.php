<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Events;

use Illuminate\Foundation\Events\Dispatchable;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;

/**
 * The scan could not be completed. Worth alerting on in its own right: a
 * fail-closed application with a broken scanner rejects every upload.
 */
final class ScanFailed
{
    use Dispatchable;

    public function __construct(
        public readonly ScanResult $result,
        public readonly ScanContext $context,
        public readonly string $reason,
    ) {}
}
