<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Scan;

use Illuminate\Support\Str;
use LaravelPlus\ContentSecurity\Exceptions\InvalidScanIdException;
use Stringable;

/**
 * Identifies one scan across the pipeline, the queue, the database and the
 * log stream. ULID rather than an auto-increment: it is generated before the
 * row exists and sorts by creation time.
 */
final readonly class ScanId implements Stringable
{
    private function __construct(public string $value) {}

    public static function generate(): self
    {
        return new self((string) Str::ulid());
    }

    public static function fromString(string $value): self
    {
        $value = trim($value);

        if (! Str::isUlid($value)) {
            throw InvalidScanIdException::for($value);
        }

        return new self($value);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }

    /** Short form for tables and log lines. */
    public function short(): string
    {
        return substr($this->value, -8);
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
