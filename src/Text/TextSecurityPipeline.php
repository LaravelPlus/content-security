<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text;

use LaravelPlus\ContentSecurity\Contracts\TextCheck;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Pipeline\PipelineRunner;

final class TextSecurityPipeline
{
    /** @var list<TextCheck> */
    private array $checks;

    /**
     * @param  list<TextCheck>  $checks
     */
    public function __construct(
        array $checks,
        private readonly PipelineRunner $runner,
    ) {
        $this->checks = $checks;
    }

    /**
     * @param  list<TextCheck>  $checks
     */
    public function withChecks(array $checks): self
    {
        return new self($checks, $this->runner);
    }

    /** @return list<TextCheck> */
    public function checks(): array
    {
        return $this->checks;
    }

    public function run(string $text, TextPolicy $policy, ScanContext $context): ScanResult
    {
        $startedAt = microtime(true);

        $applicable = array_values(array_filter(
            $this->checks,
            // `length` is not optional: it is what stops every later check
            // from being handed an unbounded string.
            static fn (TextCheck $check): bool => $check->key() === 'length' || $policy->wants($check->key()),
        ));

        $results = $this->runner->run(
            $applicable,
            fn (TextCheck $check): CheckResult => $check->check($text, $policy, $context),
        );

        foreach ($this->checks as $check) {
            if ($check->key() !== 'length' && ! $policy->wants($check->key())) {
                $results[] = CheckResult::skipped($check->key(), 'Disabled by the policy.');
            }
        }

        return ScanResult::fromChecks(
            context: $context,
            checks: $results,
            scanner: 'text-pipeline',
            durationMs: (microtime(true) - $startedAt) * 1000,
            metadata: [
                'policy' => $policy->name(),
                'length' => mb_strlen($text),
                // The text itself is never carried here. Persistence stores
                // a hash; see config('content-security.persistence').
                'checksum_sha256' => hash('sha256', $text),
            ],
        );
    }
}
