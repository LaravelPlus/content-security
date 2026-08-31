<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Checks;

use LaravelPlus\ContentSecurity\Contracts\FileCheck;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use LaravelPlus\ContentSecurity\File\Archives\ArchiveInspector;
use Throwable;

final class ArchiveCheck implements FileCheck
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
        return $this->inspector->isArchive($file);
    }

    public function check(FileReference $file, FilePolicy $policy, ScanContext $context): CheckResult
    {
        try {
            ['threats' => $threats, 'metadata' => $metadata] = $this->inspector->inspect($file);
        } catch (Throwable $e) {
            // A malformed archive must cost us a failed check, never a
            // crashed queue worker.
            return CheckResult::failed($this->key(), $e->getMessage());
        }

        if ($threats === []) {
            return CheckResult::passed($this->key(), $metadata);
        }

        $critical = array_filter(
            $threats,
            static fn (Threat $threat): bool => $threat->isAtLeast(ThreatLevel::High),
        );

        return $critical !== []
            ? CheckResult::infected($this->key(), array_values($threats), $metadata)
            : CheckResult::suspicious($this->key(), array_values($threats), $metadata);
    }
}
