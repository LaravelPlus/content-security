<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Scan;

enum ThreatLevel: string
{
    case Info = 'info';
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    public function weight(): int
    {
        return match ($this) {
            self::Info => 0,
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }

    public function atLeast(self $other): bool
    {
        return $this->weight() >= $other->weight();
    }

    public function label(): string
    {
        return ucfirst($this->value);
    }
}
