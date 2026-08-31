<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Scan;

/**
 * The outcome of one pipeline step. The admin console renders these as the
 * per-scan checklist, so a check that was switched off still reports itself
 * — "skipped" and "passed" must never look alike.
 */
final readonly class CheckResult
{
    /**
     * @param  list<Threat>  $threats
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public function __construct(
        public string $check,
        public ScanStatus $status,
        public array $threats = [],
        public array $metadata = [],
        public float $durationMs = 0.0,
        public bool $skipped = false,
        public ?string $error = null,
    ) {}

    /**
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public static function passed(string $check, array $metadata = []): self
    {
        return new self($check, ScanStatus::Clean, [], $metadata);
    }

    /**
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public static function skipped(string $check, string $reason = '', array $metadata = []): self
    {
        return new self(
            check: $check,
            status: ScanStatus::Clean,
            metadata: $reason === '' ? $metadata : [...$metadata, 'reason' => $reason],
            skipped: true,
        );
    }

    /**
     * @param  list<Threat>|Threat  $threats
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public static function suspicious(string $check, array|Threat $threats, array $metadata = []): self
    {
        return new self($check, ScanStatus::Suspicious, is_array($threats) ? $threats : [$threats], $metadata);
    }

    /**
     * @param  list<Threat>|Threat  $threats
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public static function infected(string $check, array|Threat $threats, array $metadata = []): self
    {
        return new self($check, ScanStatus::Infected, is_array($threats) ? $threats : [$threats], $metadata);
    }

    /**
     * A check that could not complete. Never a pass — see `fail_closed`.
     *
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public static function failed(string $check, string $error, array $metadata = []): self
    {
        return new self(
            check: $check,
            status: ScanStatus::Failed,
            threats: [Threat::make(
                name: 'scan.check_failed',
                level: ThreatLevel::Medium,
                source: $check,
                description: $error,
            )],
            metadata: $metadata,
            error: $error,
        );
    }

    public function withDuration(float $durationMs): self
    {
        return new self(
            $this->check,
            $this->status,
            $this->threats,
            $this->metadata,
            $durationMs,
            $this->skipped,
            $this->error,
        );
    }

    public function passedCleanly(): bool
    {
        return $this->status === ScanStatus::Clean && ! $this->skipped;
    }

    /**
     * @return array{check: string, status: string, skipped: bool, threats: list<array<string, mixed>>, metadata: array<string, mixed>, duration_ms: float, error: string|null}
     */
    public function toArray(): array
    {
        return [
            'check' => $this->check,
            'status' => $this->status->value,
            'skipped' => $this->skipped,
            'threats' => array_map(static fn (Threat $t): array => $t->toArray(), $this->threats),
            'metadata' => $this->metadata,
            'duration_ms' => round($this->durationMs, 2),
            'error' => $this->error,
        ];
    }
}
