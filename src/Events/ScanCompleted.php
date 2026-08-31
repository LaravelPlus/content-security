<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Events;

use Illuminate\Foundation\Events\Dispatchable;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;

/**
 * Fired for every completed scan, clean or not.
 */
final class ScanCompleted
{
    use Dispatchable;

    public function __construct(
        public readonly ScanResult $result,
        public readonly ScanContext $context,
    ) {}
}
