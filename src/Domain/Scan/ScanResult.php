<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Scan;

use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

/**
 * The single object every entry point returns. Only `isClean()` grants
 * passage — `failed()` is deliberately not the opposite of `isThreat()`,
 * because a scanner that could not run tells you nothing about the file.
 *
 * @implements Arrayable<string, mixed>
 */
final readonly class ScanResult implements Arrayable, JsonSerializable
{
    /**
     * @param  list<Threat>  $threats
     * @param  list<CheckResult>  $checks
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public function __construct(
        private ScanId $scanId,
        private ScanType $type,
        private ScanStatus $status,
        private array $threats = [],
        private array $checks = [],
        private string $scanner = 'pipeline',
        private float $durationMs = 0.0,
        private array $metadata = [],
    ) {}

    /**
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public static function clean(ScanContext $context, float $durationMs = 0.0, array $metadata = []): self
    {
        return new self(
            scanId: $context->scanId,
            type: $context->type,
            status: ScanStatus::Clean,
            durationMs: $durationMs,
            metadata: $metadata,
        );
    }

    /**
     * The pipeline could not run at all. `failed()` (the predicate) stays
     * the reader-facing question, so this factory is named apart from it.
     *
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public static function failure(ScanContext $context, string $reason, array $metadata = []): self
    {
        return new self(
            scanId: $context->scanId,
            type: $context->type,
            status: ScanStatus::Failed,
            threats: [Threat::make('scan.failed', ThreatLevel::Medium, 'pipeline', $reason)],
            metadata: [...$metadata, 'error' => $reason],
        );
    }

    /**
     * @param  list<CheckResult>  $checks
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public static function fromChecks(
        ScanContext $context,
        array $checks,
        string $scanner,
        float $durationMs,
        array $metadata = [],
    ): self {
        $status = ScanStatus::Clean;
        $threats = [];

        foreach ($checks as $check) {
            $status = $status->worst($check->status);
            foreach ($check->threats as $threat) {
                $threats[] = $threat;
            }
        }

        return new self(
            scanId: $context->scanId,
            type: $context->type,
            status: $status,
            threats: $threats,
            checks: $checks,
            scanner: $scanner,
            durationMs: $durationMs,
            metadata: $metadata,
        );
    }

    public function isClean(): bool
    {
        return $this->status->isSafe();
    }

    /** A definite or probable finding — not the same as a broken scanner. */
    public function isThreat(): bool
    {
        return in_array($this->status, [ScanStatus::Infected, ScanStatus::Suspicious, ScanStatus::Quarantined], true);
    }

    public function isInfected(): bool
    {
        return $this->status === ScanStatus::Infected;
    }

    public function failed(): bool
    {
        return $this->status === ScanStatus::Failed;
    }

    public function status(): ScanStatus
    {
        return $this->status;
    }

    public function type(): ScanType
    {
        return $this->type;
    }

    /** @return list<Threat> */
    public function threats(): array
    {
        return $this->threats;
    }

    /** @return list<CheckResult> */
    public function checks(): array
    {
        return $this->checks;
    }

    public function scanner(): string
    {
        return $this->scanner;
    }

    public function scanId(): ScanId
    {
        return $this->scanId;
    }

    /** Milliseconds. */
    public function duration(): float
    {
        return $this->durationMs;
    }

    /** @return array<string, scalar|array<mixed>|null> */
    public function metadata(): array
    {
        return $this->metadata;
    }

    public function highestThreatLevel(): ?ThreatLevel
    {
        $highest = null;

        foreach ($this->threats as $threat) {
            if ($highest === null || $threat->level->weight() > $highest->weight()) {
                $highest = $threat->level;
            }
        }

        return $highest;
    }

    /**
     * The first line worth showing a developer. Deliberately generic about
     * *why* — end users must not learn which check they tripped.
     */
    public function summary(): string
    {
        if ($this->isClean()) {
            return 'No threats detected.';
        }

        if ($this->failed()) {
            return 'The security scan could not be completed.';
        }

        $count = count($this->threats);

        return $count === 1
            ? 'A security threat was detected.'
            : sprintf('%d security threats were detected.', $count);
    }

    public function withStatus(ScanStatus $status): self
    {
        return new self(
            $this->scanId,
            $this->type,
            $status,
            $this->threats,
            $this->checks,
            $this->scanner,
            $this->durationMs,
            $this->metadata,
        );
    }

    /**
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public function withMetadata(array $metadata): self
    {
        return new self(
            $this->scanId,
            $this->type,
            $this->status,
            $this->threats,
            $this->checks,
            $this->scanner,
            $this->durationMs,
            [...$this->metadata, ...$metadata],
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'scan_id' => (string) $this->scanId,
            'type' => $this->type->value,
            'status' => $this->status->value,
            'scanner' => $this->scanner,
            'duration_ms' => round($this->durationMs, 2),
            'threats' => array_map(static fn (Threat $t): array => $t->toArray(), $this->threats),
            'checks' => array_map(static fn (CheckResult $c): array => $c->toArray(), $this->checks),
            'metadata' => $this->metadata,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
