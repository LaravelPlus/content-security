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
        /**
         * Whether this is the driver the application actually scans with.
         * Every configured driver is reported, so without this an idle
         * `null` entry reads exactly like a missing engine.
         */
        public bool $active = false,
        public array $details = [],
    ) {}

    public function asActive(bool $active = true): self
    {
        return new self(
            scanner: $this->scanner,
            online: $this->online,
            version: $this->version,
            signatureVersion: $this->signatureVersion,
            signaturesUpdatedAt: $this->signaturesUpdatedAt,
            pingMs: $this->pingMs,
            connection: $this->connection,
            error: $this->error,
            enabled: $this->enabled,
            active: $active,
            details: $this->details,
        );
    }

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
            ! $this->enabled => $this->active ? 'unconfigured' : 'inactive',
            $this->online => 'online',
            default => 'offline',
        };
    }

    /**
     * True only when the engine the application scans with cannot scan.
     * An idle driver sitting in config is not a problem; the active one
     * being absent or unreachable is.
     */
    public function isProblem(): bool
    {
        return $this->active && ! $this->online;
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
            'active' => $this->active,
            'is_problem' => $this->isProblem(),
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
