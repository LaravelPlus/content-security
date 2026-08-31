<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Scan;

/**
 * What an inspector found, and what it observed on the way.
 *
 * Inspectors used to hand back `array{threats: …, metadata: …}`, which is a
 * shape you can only learn by reading the callee. This is the same data with
 * a name — and it is where "how bad is this?" lives, so no two checks answer
 * that question differently.
 */
final readonly class Findings
{
    /**
     * @param  list<Threat>  $threats
     * @param  array<string, mixed>  $metadata
     */
    public function __construct(
        public array $threats = [],
        public array $metadata = [],
    ) {}

    /**
     * @param  array<string, mixed>  $metadata
     */
    public static function none(array $metadata = []): self
    {
        return new self([], $metadata);
    }

    /**
     * @param  list<Threat>|Threat  $threats
     * @param  array<string, mixed>  $metadata
     */
    public static function of(array|Threat $threats, array $metadata = []): self
    {
        return new self(is_array($threats) ? array_values($threats) : [$threats], $metadata);
    }

    public function isEmpty(): bool
    {
        return $this->threats === [];
    }

    public function hasAtLeast(ThreatLevel $level): bool
    {
        foreach ($this->threats as $threat) {
            if ($threat->isAtLeast($level)) {
                return true;
            }
        }

        return false;
    }

    public function highestLevel(): ?ThreatLevel
    {
        $highest = null;

        foreach ($this->threats as $threat) {
            if ($highest === null || $threat->level->weight() > $highest->weight()) {
                $highest = $threat->level;
            }
        }

        return $highest;
    }

    public function merge(self $other): self
    {
        return new self(
            [...$this->threats, ...$other->threats],
            [...$this->metadata, ...$other->metadata],
        );
    }

    /**
     * @param  array<string, mixed>  $metadata
     */
    public function withMetadata(array $metadata): self
    {
        return new self($this->threats, [...$this->metadata, ...$metadata]);
    }
}
