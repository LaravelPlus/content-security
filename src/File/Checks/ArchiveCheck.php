<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Checks;

use LaravelPlus\ContentSecurity\Contracts\ArchiveInspector;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;

final class ArchiveCheck extends AbstractFileCheck
{
    public function __construct(private readonly ArchiveInspector $inspector) {}

    public function key(): string
    {
        return 'archive';
    }

    public function label(): string
    {
        return 'Archive inspection';
    }

    public function appliesTo(FileReference $file, FilePolicy $policy): bool
    {
        return $this->inspector->handles($file);
    }

    protected function inspect(FileReference $file, FilePolicy $policy, ScanContext $context): Findings
    {
        return $this->inspector->inspect($file);
    }
}
