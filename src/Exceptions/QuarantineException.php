<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Exceptions;

final class QuarantineException extends ContentSecurityException
{
    public static function writeFailed(string $disk, string $path): self
    {
        return new self(sprintf('Could not write the quarantined file to [%s] on disk [%s].', $path, $disk));
    }

    public static function notQuarantined(string $scanId): self
    {
        return new self(sprintf('Scan [%s] has no quarantined file.', $scanId));
    }

    public static function releaseRequiresCleanScan(string $scanId): self
    {
        return new self(sprintf('Scan [%s] cannot be released: the most recent scan is not clean.', $scanId));
    }

    public static function missingFile(string $path): self
    {
        return new self(sprintf('The quarantined file [%s] is no longer on the quarantine disk.', $path));
    }
}
