<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Archives;

/**
 * Bounds on the work an archive is allowed to cost us. Without these, a
 * 42 KB zip expands to petabytes and takes the worker with it.
 */
final readonly class ArchiveLimits
{
    /**
     * @param  list<string>  $forbiddenEntryExtensions
     */
    public function __construct(
        public int $maxDepth,
        public int $maxFiles,
        public int $maxUncompressedSize,
        public int $maxCompressionRatio,
        public array $forbiddenEntryExtensions,
    ) {}

    public static function fromConfig(): self
    {
        /** @var list<string> $forbidden */
        $forbidden = (array) (
            config('content-security.archives.forbidden_entry_extensions')
            ?? config('content-security.files.forbidden_extensions', [])
        );

        return new self(
            maxDepth: (int) config('content-security.archives.max_depth', 3),
            maxFiles: (int) config('content-security.archives.max_files', 500),
            maxUncompressedSize: (int) config('content-security.archives.max_uncompressed_size', 500 * 1024 * 1024),
            maxCompressionRatio: (int) config('content-security.archives.max_compression_ratio', 100),
            forbiddenEntryExtensions: array_values(array_map(
                static fn (string $ext): string => mb_strtolower(ltrim($ext, '.')),
                $forbidden,
            )),
        );
    }
}
