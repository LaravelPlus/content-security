<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

use LaravelPlus\ContentSecurity\Domain\File\FileReference;

interface ImageInspector extends FileInspector
{
    public function isVector(FileReference $file): bool;

    /** True when the file was rewritten from decoded pixels. */
    public function reencode(FileReference $file): bool;

    public function reencodes(): bool;

    public function stripsMetadata(): bool;
}
