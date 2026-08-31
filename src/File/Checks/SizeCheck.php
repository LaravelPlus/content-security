<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Checks;

use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use LaravelPlus\ContentSecurity\Support\Bytes;

/**
 * First in the pipeline on purpose: every later check costs work in
 * proportion to the file, so an oversized upload is stopped before anything
 * reads it.
 */
final class SizeCheck extends AbstractFileCheck
{
    public function key(): string
    {
        return 'size';
    }

    public function label(): string
    {
        return 'File size';
    }

    protected function inspect(FileReference $file, FilePolicy $policy, ScanContext $context): Findings
    {
        $size = $file->size();
        $metadata = ['size' => $size, 'max_size' => $policy->maxSize];

        if ($size === 0) {
            return Findings::of(Threat::make(
                name: 'file.empty',
                level: ThreatLevel::Low,
                source: $this->key(),
                description: 'The file is empty.',
            ), $metadata);
        }

        if ($size > $policy->maxSize) {
            return Findings::of(Threat::make(
                name: 'file.too_large',
                // A policy rejection, not dangerous content — so the scan
                // reads Suspicious rather than Infected. It still fails
                // isClean(), which is what refuses the upload.
                level: ThreatLevel::Medium,
                source: $this->key(),
                description: sprintf(
                    'File is %s; the policy allows %s.',
                    Bytes::humanize($size),
                    Bytes::humanize($policy->maxSize),
                ),
                metadata: $metadata,
            ), $metadata);
        }

        return Findings::none($metadata);
    }
}
