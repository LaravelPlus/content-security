<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Exceptions;

final class InvalidFileException extends ContentSecurityException
{
    public static function unreadable(string $name): self
    {
        return new self(sprintf('File [%s] is missing or unreadable.', $name));
    }

    public static function missingOnDisk(string $disk, string $path): self
    {
        return new self(sprintf('File [%s] does not exist on disk [%s].', $path, $disk));
    }

    public static function temporaryFileFailed(): self
    {
        return new self('Could not create a temporary file for scanning.');
    }

    public static function tooLargeToScan(int $size, int $limit): self
    {
        return new self(sprintf('File of %d bytes exceeds the scannable limit of %d bytes.', $size, $limit));
    }
}
