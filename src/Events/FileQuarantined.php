<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Events;

use Illuminate\Foundation\Events\Dispatchable;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;

final class FileQuarantined
{
    use Dispatchable;

    public function __construct(
        public readonly ScanId $scanId,
        public readonly string $disk,
        public readonly string $path,
        public readonly ?ScanResult $result = null,
    ) {}
}
