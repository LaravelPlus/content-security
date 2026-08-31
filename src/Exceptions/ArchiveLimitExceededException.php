<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Exceptions;

final class ArchiveLimitExceededException extends ContentSecurityException
{
    public static function limit(string $limit, int|float $actual, int|float $allowed): self
    {
        return new self(sprintf('Archive exceeded the %s limit (%s > %s).', $limit, (string) $actual, (string) $allowed));
    }
}
