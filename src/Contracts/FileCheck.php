<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;

interface FileCheck extends SecurityCheck
{
    public function check(FileReference $file, FilePolicy $policy, ScanContext $context): CheckResult;

    /**
     * Lets a check bow out for input it cannot say anything about — the PDF
     * check on a PNG, say. Cheaper and more honest than a pass.
     */
    public function appliesTo(FileReference $file, FilePolicy $policy): bool;
}
