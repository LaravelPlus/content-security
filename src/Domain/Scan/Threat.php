<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Scan;

use JsonSerializable;

/**
 * One finding. `name` is the signature or rule that fired, `source` is the
 * check or engine that fired it.
 */
final readonly class Threat implements JsonSerializable
{
    /**
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public function __construct(
        public string $name,
        public ThreatLevel $level,
        public string $source,
        public ?string $description = null,
        public array $metadata = [],
    ) {}

    /**
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public static function make(
        string $name,
        ThreatLevel $level,
        string $source,
        ?string $description = null,
        array $metadata = [],
    ): self {
        return new self($name, $level, $source, $description, $metadata);
    }

    public function isAtLeast(ThreatLevel $level): bool
    {
        return $this->level->atLeast($level);
    }

    /**
     * @return array{name: string, level: string, source: string, description: string|null, metadata: array<string, mixed>}
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'level' => $this->level->value,
            'source' => $this->source,
            'description' => $this->description,
            'metadata' => $this->metadata,
        ];
    }

    /**
     * @return array{name: string, level: string, source: string, description: string|null, metadata: array<string, mixed>}
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
