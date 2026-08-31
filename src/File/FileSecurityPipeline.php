<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File;

use LaravelPlus\ContentSecurity\Contracts\FileCheck;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Pipeline\PipelineRunner;

/**
 * Order matters, and it is cheapest-first:
 *
 *   size → extension → MIME → magic bytes → archive → image → PDF → malware
 *
 * Everything before `malware` is a few syscalls; the malware step is a
 * network round trip and a full stream of the file. Rejecting a 900 MB
 * .php upload on its extension costs microseconds, so the daemon never
 * sees it.
 */
final class FileSecurityPipeline
{
    /** @var list<FileCheck> */
    private array $checks;

    /**
     * @param  list<FileCheck>  $checks
     */
    public function __construct(
        array $checks,
        private readonly PipelineRunner $runner,
    ) {
        $this->checks = $checks;
    }

    /**
     * @param  list<FileCheck>  $checks
     */
    public function withChecks(array $checks): self
    {
        return new self($checks, $this->runner);
    }

    /** @return list<FileCheck> */
    public function checks(): array
    {
        return $this->checks;
    }

    public function run(FileReference $file, FilePolicy $policy, ScanContext $context): ScanResult
    {
        $startedAt = microtime(true);

        $applicable = array_values(array_filter(
            $this->checks,
            static fn (FileCheck $check): bool => $policy->wants($check->key()),
        ));

        $results = $this->runner->run(
            $applicable,
            function (FileCheck $check) use ($file, $policy, $context): CheckResult {
                if (! $check->appliesTo($file, $policy)) {
                    return CheckResult::skipped($check->key(), 'Not applicable to this file type.');
                }

                return $check->check($file, $policy, $context);
            },
        );

        // Checks the policy switched off are recorded, not omitted: a
        // console that silently drops them makes a disabled malware scan
        // look identical to a passing one.
        foreach ($this->checks as $check) {
            if (! $policy->wants($check->key())) {
                $results[] = CheckResult::skipped($check->key(), 'Disabled by the policy.');
            }
        }

        return ScanResult::fromChecks(
            context: $context,
            checks: $results,
            scanner: 'file-pipeline',
            durationMs: (microtime(true) - $startedAt) * 1000,
            metadata: [
                'policy' => $policy->name(),
                ...$file->describe(),
            ],
        );
    }
}
