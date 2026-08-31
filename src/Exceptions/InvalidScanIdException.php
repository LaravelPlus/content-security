<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Exceptions;

final class InvalidScanIdException extends ContentSecurityException
{
    public static function for(string $value): self
    {
        return new self(sprintf('[%s] is not a valid scan id.', $value));
    }
}
