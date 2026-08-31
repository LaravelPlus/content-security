<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Exceptions;

final class PolicyNotFoundException extends ContentSecurityException
{
    /** @param list<array-key> $available */
    public static function file(string $name, array $available): self
    {
        return new self(sprintf(
            'File policy [%s] is not defined in content-security.files.policies. Available: %s.',
            $name,
            implode(', ', array_map(strval(...), $available)) ?: 'none',
        ));
    }

    /** @param list<array-key> $available */
    public static function text(string $name, array $available): self
    {
        return new self(sprintf(
            'Text policy [%s] is not defined in content-security.text.policies. Available: %s.',
            $name,
            implode(', ', array_map(strval(...), $available)) ?: 'none',
        ));
    }
}
