<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Events;

use Illuminate\Foundation\Events\Dispatchable;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;

final class ScanStarted
{
    use Dispatchable;

    public function __construct(public readonly ScanContext $context) {}
}
