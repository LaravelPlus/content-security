<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Support;

use DateTimeImmutable;

/**
 * What the health page renders for one engine. Connection strings are shown
 * because an operator needs them; secrets never belong in this object.
 */
final readonly class ScannerHealth
{
    /**
     * @param  array<string, scalar|null>  $details
     */
    public function __construct(
        public string $scanner,
        public bool $online,
        public ?string $version = null,
        public ?string $signatureVersion = null,
        public ?DateTimeImmutable $signaturesUpdatedAt = null,
        public ?float $pingMs = null,
        public ?string $connection = null,
        public ?string $error = null,
        public bool $enabled = true,
        public array $details = [],
    ) {}

    public static function offline(string $scanner, string $error, ?string $connection = null): self
    {
        return new self(
            scanner: $scanner,
            online: false,
            connection: $connection,
            error: $error,
        );
    }

    public static function disabled(string $scanner, string $reason = 'Driver disabled'): self
    {
        return new self(
            scanner: $scanner,
            online: false,
            error: $reason,
            enabled: false,
        );
    }

    public function status(): string
    {
        return match (true) {
            ! $this->enabled => 'disabled',
            $this->online => 'online',
            default => 'offline',
        };
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'scanner' => $this->scanner,
            'status' => $this->status(),
            'online' => $this->online,
            'enabled' => $this->enabled,
            'version' => $this->version,
            'signature_version' => $this->signatureVersion,
            'signatures_updated_at' => $this->signaturesUpdatedAt?->format(DATE_ATOM),
            'ping_ms' => $this->pingMs === null ? null : round($this->pingMs, 2),
            'connection' => $this->connection,
            'error' => $this->error,
            'details' => $this->details,
        ];
    }
}
