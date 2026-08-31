<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;

interface FileInspector extends Inspector
{
    /** Whether this inspector recognises the file at all. */
    public function handles(FileReference $file): bool;

    public function inspect(FileReference $file): Findings;
}
