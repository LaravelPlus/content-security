<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Checks;

use LaravelPlus\ContentSecurity\Contracts\FileCheck;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use Throwable;

/**
 * Base for file checks, and the single place that decides how a set of
 * findings becomes a verdict.
 *
 * That rule — High or Critical blocks, anything lower is suspicious — was
 * previously repeated in five checks, where five copies could quietly drift
 * apart. Subclasses describe *what* they found; severity is not theirs to
 * reinterpret.
 *
 * Extend this to add a check of your own, then register it with
 * ContentSecurity::addFileCheck().
 */
abstract class AbstractFileCheck implements FileCheck
{
    /** The level at which a finding rejects the file rather than flagging it. */
    protected const BLOCKING_LEVEL = ThreatLevel::High;

    abstract public function key(): string;

    abstract public function label(): string;

    /**
     * Subclasses report; they do not score. Throwing is allowed — it is
     * caught here and becomes a failed check, never a pass.
     */
    abstract protected function inspect(FileReference $file, FilePolicy $policy, ScanContext $context): Findings;

    public function appliesTo(FileReference $file, FilePolicy $policy): bool
    {
        return true;
    }

    final public function check(FileReference $file, FilePolicy $policy, ScanContext $context): CheckResult
    {
        try {
            $findings = $this->inspect($file, $policy, $context);
        } catch (Throwable $e) {
            return CheckResult::failed($this->key(), $e->getMessage());
        }

        return $this->verdict($findings);
    }

    final protected function verdict(Findings $findings): CheckResult
    {
        if ($findings->isEmpty()) {
            return CheckResult::passed($this->key(), $findings->metadata);
        }

        return $findings->hasAtLeast(static::BLOCKING_LEVEL)
            ? CheckResult::infected($this->key(), $findings->threats, $findings->metadata)
            : CheckResult::suspicious($this->key(), $findings->threats, $findings->metadata);
    }
}
