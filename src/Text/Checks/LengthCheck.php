<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\Checks;

use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * Runs first, and cannot be switched off: it is what stops every pattern
 * check below from being handed an unbounded string.
 */
final class LengthCheck extends AbstractTextCheck
{
    public function key(): string
    {
        return 'length';
    }

    public function label(): string
    {
        return 'Length';
    }

    protected function inspect(string $text, TextPolicy $policy, ScanContext $context): Findings
    {
        $length = mb_strlen($text);
        $metadata = ['length' => $length, 'max_length' => $policy->maxLength];

        if ($length > $policy->maxLength) {
            return Findings::of(Threat::make(
                name: 'text.too_long',
                level: ThreatLevel::Medium,
                source: $this->key(),
                description: sprintf(
                    'The text is %d characters; the policy allows %d.',
                    $length,
                    $policy->maxLength,
                ),
                metadata: $metadata,
            ), $metadata);
        }

        return Findings::none($metadata);
    }
}
