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
use LaravelPlus\ContentSecurity\Support\Bytes;

/**
 * First in the pipeline on purpose: every later check costs CPU proportional
 * to the file, so an oversized file is rejected before anything reads it.
 */
final class SizeCheck implements FileCheck
{
    public function key(): string
    {
        return 'size';
    }

    public function label(): string
    {
        return 'File size';
    }

    public function appliesTo(FileReference $file, FilePolicy $policy): bool
    {
        return true;
    }

    public function check(FileReference $file, FilePolicy $policy, ScanContext $context): CheckResult
    {
        $size = $file->size();

        if ($size === 0) {
            return CheckResult::suspicious($this->key(), Threat::make(
                name: 'file.empty',
                level: ThreatLevel::Low,
                source: $this->key(),
                description: 'The file is empty.',
            ), ['size' => 0]);
        }

        if ($size > $policy->maxSize) {
            return CheckResult::infected($this->key(), Threat::make(
                name: 'file.too_large',
                level: ThreatLevel::Medium,
                source: $this->key(),
                description: sprintf(
                    'File is %s; the policy allows %s.',
                    Bytes::humanize($size),
                    Bytes::humanize($policy->maxSize),
                ),
                metadata: ['size' => $size, 'max_size' => $policy->maxSize],
            ), ['size' => $size, 'max_size' => $policy->maxSize]);
        }

        return CheckResult::passed($this->key(), ['size' => $size, 'max_size' => $policy->maxSize]);
    }
}
