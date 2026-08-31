<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Scan;

/**
 * Everything a scan needs to know about *why* it is running: which scan it
 * is, what kind, under which policy, and who asked. Carried through the
 * pipeline so checks, events and log lines all agree on identity.
 */
final readonly class ScanContext
{
    /**
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public function __construct(
        public ScanId $scanId,
        public ScanType $type,
        public string $policy,
        public ?string $requestId = null,
        public int|string|null $userId = null,
        public array $metadata = [],
    ) {}

    public static function for(ScanType $type, string $policy, ?ScanId $scanId = null): self
    {
        return new self(
            scanId: $scanId ?? ScanId::generate(),
            type: $type,
            policy: $policy,
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
            $this->policy,
            $this->requestId,
            $this->userId,
            [...$this->metadata, ...$metadata],
        );
    }

    public function withActor(int|string|null $userId, ?string $requestId = null): self
    {
        return new self(
            $this->scanId,
            $this->type,
            $this->policy,
            $requestId ?? $this->requestId,
            $userId,
            $this->metadata,
        );
    }
}
