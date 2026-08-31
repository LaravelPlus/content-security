<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\Checks;

use LaravelPlus\ContentSecurity\Contracts\TextInspector;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;

final class SuspiciousContentCheck extends AbstractTextCheck
{
    public function __construct(private readonly TextInspector $inspector) {}

    public function key(): string
    {
        return 'suspicious';
    }

    public function label(): string
    {
        return 'Suspicious content';
    }

    protected function inspect(string $text, TextPolicy $policy, ScanContext $context): Findings
    {
        return $this->inspector->inspect($text);
    }
}
