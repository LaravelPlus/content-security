<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Events;

use Illuminate\Foundation\Events\Dispatchable;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;

final class QuarantineDeleted
{
    use Dispatchable;

    public function __construct(
        public readonly ScanId $scanId,
        public readonly int|string|null $actorId,
    ) {}
}
