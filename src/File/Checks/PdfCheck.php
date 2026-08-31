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
use LaravelPlus\ContentSecurity\File\Pdf\PdfInspector;
use Throwable;

final class PdfCheck implements FileCheck
{
    public function __construct(private readonly PdfInspector $inspector) {}

    public function key(): string
    {
        return 'pdf';
    }

    public function label(): string
    {
        return 'PDF inspection';
    }

    public function appliesTo(FileReference $file, FilePolicy $policy): bool
    {
        return $this->inspector->isPdf($file);
    }

    public function check(FileReference $file, FilePolicy $policy, ScanContext $context): CheckResult
    {
        try {
            ['threats' => $threats, 'metadata' => $metadata] = $this->inspector->inspect($file);
        } catch (Throwable $e) {
            return CheckResult::failed($this->key(), $e->getMessage());
        }

        if ($threats === []) {
            return CheckResult::passed($this->key(), $metadata);
        }

        $blocking = array_filter(
            $threats,
            static fn (Threat $threat): bool => $threat->isAtLeast(ThreatLevel::High),
        );

        return $blocking !== []
            ? CheckResult::infected($this->key(), array_values($threats), $metadata)
            : CheckResult::suspicious($this->key(), array_values($threats), $metadata);
    }
}
