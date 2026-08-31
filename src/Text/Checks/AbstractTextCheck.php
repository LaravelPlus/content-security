<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\Checks;

use LaravelPlus\ContentSecurity\Contracts\TextCheck;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use Throwable;

/**
 * Base for text checks. Same contract as AbstractFileCheck: the subclass
 * reports findings, this class turns them into a verdict.
 *
 * Extend it and register with ContentSecurity::addTextCheck().
 */
abstract class AbstractTextCheck implements TextCheck
{
    protected const BLOCKING_LEVEL = ThreatLevel::High;

    abstract public function key(): string;

    abstract public function label(): string;

    abstract protected function inspect(string $text, TextPolicy $policy, ScanContext $context): Findings;

    final public function check(string $text, TextPolicy $policy, ScanContext $context): CheckResult
    {
        try {
            $findings = $this->inspect($text, $policy, $context);
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

        if ($findings->hasAtLeast(static::BLOCKING_LEVEL)) {
            return CheckResult::infected($this->key(), $findings->threats, $findings->metadata);
        }

        // Info is an observation, not a verdict. Without this, a browser
        // sending `application/octet-stream` for an ordinary PNG — which is
        // routine — produced a Suspicious scan and every such upload was
        // rejected. The finding is still recorded; it just does not decide.
        if (! $findings->hasAtLeast(ThreatLevel::Low)) {
            return CheckResult::informational($this->key(), $findings->threats, $findings->metadata);
        }

        return CheckResult::suspicious($this->key(), $findings->threats, $findings->metadata);
    }
}
