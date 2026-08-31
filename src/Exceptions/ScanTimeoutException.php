<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Exceptions;

final class ScanTimeoutException extends ContentSecurityException
{
    public static function after(string $scanner, int $seconds): self
    {
        return new self(sprintf('Scanner [%s] did not respond within %d seconds.', $scanner, $seconds));
    }
}
