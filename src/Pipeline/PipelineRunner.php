<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Pipeline;

use LaravelPlus\ContentSecurity\Contracts\SecurityCheck;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use Throwable;

/**
 * Runs an ordered list of checks and collects their results.
 *
 * Three rules, and they are the security model:
 *
 *  1. A check that throws becomes a FAILED result. It never becomes a pass,
 *     and it never escapes to kill the queue worker.
 *  2. Under `fail_closed`, one failed check ends the run — there is nothing
 *     to learn from the remaining checks once the verdict cannot be clean.
 *  3. A definite finding (Infected) also ends the run. The file is already
 *     rejected; further work is spent on a decided outcome.
 */
final class PipelineRunner
{
    public function __construct(private readonly bool $failClosed) {}

    public static function fromConfig(): self
    {
        return new self((bool) config('content-security.fail_closed', true));
    }

    /**
     * Generic over the check type so a file pipeline can pass a
     * callable(FileCheck) and a text pipeline a callable(TextCheck) — PHP
     * parameter types are contravariant, and a plain callable(SecurityCheck)
     * would reject both.
     *
     * @template TCheck of SecurityCheck
     *
     * @param  list<TCheck>  $checks
     * @param  callable(TCheck): CheckResult  $run
     * @return list<CheckResult>
     */
    public function run(array $checks, callable $run): array
    {
        $results = [];

        foreach ($checks as $check) {
            $startedAt = microtime(true);

            try {
                $result = $run($check);
            } catch (Throwable $e) {
                // Defensive on purpose: a check is allowed to be wrong, it
                // is not allowed to take the process with it. Malformed
                // input is the normal case here, not the exception.
                $result = CheckResult::failed($check->key(), $e->getMessage());
            }

            $results[] = $result->withDuration((microtime(true) - $startedAt) * 1000);

            if ($this->shouldStop($result)) {
                break;
            }
        }

        return $results;
    }

    private function shouldStop(CheckResult $result): bool
    {
        if ($result->status === ScanStatus::Infected) {
            return true;
        }

        return $this->failClosed && $result->status === ScanStatus::Failed;
    }
}
