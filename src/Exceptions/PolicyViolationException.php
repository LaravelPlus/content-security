<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Exceptions;

use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;

/**
 * Thrown by the throwing variants of the API (`scanFileOrFail`). The result
 * travels with it so a caller can audit what actually fired.
 */
final class PolicyViolationException extends ContentSecurityException
{
    private function __construct(string $message, public readonly ScanResult $result)
    {
        parent::__construct($message);
    }

    public static function from(ScanResult $result): self
    {
        return new self($result->summary(), $result);
    }
}
