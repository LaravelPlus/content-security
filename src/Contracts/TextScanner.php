<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;

interface TextScanner
{
    public function scanText(string $text, TextPolicy|string|null $policy = null): ScanResult;
}
