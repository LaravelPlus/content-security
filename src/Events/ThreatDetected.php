<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Events;

use Illuminate\Foundation\Events\Dispatchable;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;

/**
 * One event per threat, not one per scan — a listener that pages someone
 * wants the finding, not a bag of them.
 */
final class ThreatDetected
{
    use Dispatchable;

    public function __construct(
        public readonly Threat $threat,
        public readonly ScanResult $result,
        public readonly ScanContext $context,
    ) {}
}
