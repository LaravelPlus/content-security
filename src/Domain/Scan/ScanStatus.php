<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Scan;

enum ScanStatus: string
{
    case Pending = 'pending';
    case Scanning = 'scanning';
    case Clean = 'clean';
    case Suspicious = 'suspicious';
    case Infected = 'infected';
    case Failed = 'failed';
    case Quarantined = 'quarantined';

    /**
     * How bad this status is. Aggregating a pipeline keeps the worst one, so
     * a single infected check cannot be voted down by nine clean ones.
     */
    public function severity(): int
    {
        return match ($this) {
            self::Pending => 0,
            self::Scanning => 1,
            self::Clean => 2,
            self::Suspicious => 3,
            self::Failed => 4,
            self::Infected => 5,
            self::Quarantined => 6,
        };
    }

    public function isTerminal(): bool
    {
        return ! in_array($this, [self::Pending, self::Scanning], true);
    }

    /**
     * Only Clean is safe. Everything else — including Failed — is not, which
     * is what "fail closed" means in practice.
     */
    public function isSafe(): bool
    {
        return $this === self::Clean;
    }

    public function worst(self $other): self
    {
        return $other->severity() > $this->severity() ? $other : $this;
    }

    public function label(): string
    {
        return ucfirst($this->value);
    }
}
