<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\Checks;

use LaravelPlus\ContentSecurity\Contracts\TextCheck;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use LaravelPlus\ContentSecurity\Text\SuspiciousContent\SuspiciousContentScanner;

final class SuspiciousContentCheck implements TextCheck
{
    public function __construct(private readonly SuspiciousContentScanner $scanner) {}

    public function key(): string
    {
        return 'suspicious';
    }

    public function label(): string
    {
        return 'Suspicious content';
    }

    public function check(string $text, TextPolicy $policy, ScanContext $context): CheckResult
    {
        ['threats' => $threats, 'metadata' => $metadata] = $this->scanner->inspect($text);

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
