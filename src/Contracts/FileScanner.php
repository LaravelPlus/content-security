<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

use Illuminate\Http\UploadedFile;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;

/**
 * Named `scanFile` rather than `scan` so one class can implement both this
 * and TextScanner — which ContentSecurity does, and which PHP forbids when
 * two interfaces declare the same method with different signatures.
 */
interface FileScanner
{
    public function scanFile(UploadedFile|FileReference|string $file, FilePolicy|string|null $policy = null): ScanResult;
}
