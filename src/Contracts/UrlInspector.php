<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

use LaravelPlus\ContentSecurity\Domain\Scan\Findings;

interface UrlInspector extends Inspector
{
    public function inspect(string $url): Findings;

    /** Convenience for the validation rule: no finding at Medium or above. */
    public function isSafe(string $url): bool;
}
