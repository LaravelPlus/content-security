<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Exceptions;

/**
 * The engine could not be reached. Never downgrade this to "clean" — a
 * silent scanner outage that accepts every upload is the exact failure this
 * package exists to prevent.
 */
final class ScannerUnavailableException extends ContentSecurityException
{
    public static function connection(string $scanner, string $target, string $reason): self
    {
        return new self(sprintf('Scanner [%s] is unreachable at [%s]: %s', $scanner, $target, $reason));
    }

    public static function driver(string $driver): self
    {
        return new self(sprintf('Malware scanner driver [%s] is not registered.', $driver));
    }

    public static function response(string $scanner, string $response): self
    {
        return new self(sprintf('Scanner [%s] returned an unusable response: %s', $scanner, $response));
    }

    public static function binaryMissing(string $binary): self
    {
        return new self(sprintf('Scanner binary [%s] was not found on PATH.', $binary));
    }
}
