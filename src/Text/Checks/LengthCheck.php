<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\Checks;

use LaravelPlus\ContentSecurity\Contracts\TextCheck;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * Runs first so the pattern checks below never face a 40 MB string.
 */
final class LengthCheck implements TextCheck
{
    public function key(): string
    {
        return 'length';
    }

    public function label(): string
    {
        return 'Length';
    }

    public function check(string $text, TextPolicy $policy, ScanContext $context): CheckResult
    {
        $length = mb_strlen($text);

        if ($length > $policy->maxLength) {
            return CheckResult::infected($this->key(), Threat::make(
                name: 'text.too_long',
                level: ThreatLevel::Medium,
                source: $this->key(),
                description: sprintf('The text is %d characters; the policy allows %d.', $length, $policy->maxLength),
                metadata: ['length' => $length, 'max_length' => $policy->maxLength],
            ), ['length' => $length, 'max_length' => $policy->maxLength]);
        }

        return CheckResult::passed($this->key(), ['length' => $length, 'max_length' => $policy->maxLength]);
    }
}
