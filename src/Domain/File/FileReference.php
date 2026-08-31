<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\File;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use LaravelPlus\ContentSecurity\Exceptions\InvalidFileException;

/**
 * A file the pipeline can read, decoupled from how it arrived.
 *
 * Everything downstream reads through `stream()` — nothing loads the file
 * into memory, so a 500 MB upload costs a buffer, not 500 MB of PHP heap.
 * The declared MIME type and original filename are recorded because they are
 * evidence, never because they are trusted.
 */
final class FileReference
{
    private ?string $checksum = null;

    private ?int $size = null;

    private function __construct(
        public readonly string $path,
        public readonly string $originalName,
        public readonly ?string $declaredMime,
        public readonly bool $temporary = false,
        public readonly ?string $disk = null,
        public readonly ?string $diskPath = null,
    ) {}

    public static function fromUploadedFile(UploadedFile $file): self
    {
        $path = $file->getRealPath();

        if ($path === false || ! is_readable($path)) {
            throw InvalidFileException::unreadable($file->getClientOriginalName());
        }

        return new self(
            path: $path,
            originalName: $file->getClientOriginalName(),
            // getClientMimeType() is the browser's claim. getMimeType() would
            // sniff the file, which is the MimeCheck's job, not the value
            // object's — keeping them apart is what makes a mismatch visible.
            declaredMime: $file->getClientMimeType(),
        );
    }

    public static function fromPath(string $path, ?string $originalName = null, ?string $declaredMime = null): self
    {
        if (! is_file($path) || ! is_readable($path)) {
            throw InvalidFileException::unreadable($path);
        }

        return new self(
            path: $path,
            originalName: $originalName ?? basename($path),
            declaredMime: $declaredMime,
        );
    }

    /**
     * Streams a file off any Flysystem disk into a local temporary copy —
     * finfo, ZipArchive and clamd all need a real file descriptor. Call
     * `discardTemporary()` when the scan is done.
     */
    public static function fromDisk(string $disk, string $diskPath, ?string $originalName = null): self
    {
        $filesystem = Storage::disk($disk);

        if (! $filesystem->exists($diskPath)) {
            throw InvalidFileException::missingOnDisk($disk, $diskPath);
        }

        $source = $filesystem->readStream($diskPath);

        if (! is_resource($source)) {
            throw InvalidFileException::unreadable($diskPath);
        }

        $temp = tempnam(sys_get_temp_dir(), 'cs-scan-');

        if ($temp === false) {
            throw InvalidFileException::temporaryFileFailed();
        }

        $target = fopen($temp, 'wb');

        if (! is_resource($target)) {
            @unlink($temp);
            throw InvalidFileException::temporaryFileFailed();
        }

        try {
            stream_copy_to_stream($source, $target);
        } finally {
            fclose($target);
            fclose($source);
        }

        return new self(
            path: $temp,
            originalName: $originalName ?? basename($diskPath),
            declaredMime: null,
            temporary: true,
            disk: $disk,
            diskPath: $diskPath,
        );
    }

    public function size(): int
    {
        if ($this->size === null) {
            $size = @filesize($this->path);
            $this->size = $size === false ? 0 : $size;
        }

        return $this->size;
    }

    /** Lowercased, without the dot. Empty string when the name carries none. */
    public function extension(): string
    {
        return Str::lower(pathinfo($this->originalName, PATHINFO_EXTENSION));
    }

    /**
     * SHA-256, streamed. MD5 is not a security checksum and is not offered.
     */
    public function checksum(): string
    {
        if ($this->checksum === null) {
            $hash = @hash_file('sha256', $this->path);
            $this->checksum = $hash === false ? '' : $hash;
        }

        return $this->checksum;
    }

    /**
     * @return resource
     */
    public function stream(string $mode = 'rb')
    {
        $handle = @fopen($this->path, $mode);

        if (! is_resource($handle)) {
            throw InvalidFileException::unreadable($this->path);
        }

        return $handle;
    }

    /** First N bytes — enough for magic numbers and header sniffing. */
    public function head(int $bytes = 4096): string
    {
        $handle = $this->stream();

        try {
            $head = fread($handle, $bytes);
        } finally {
            fclose($handle);
        }

        return $head === false ? '' : $head;
    }

    public function discardTemporary(): void
    {
        if ($this->temporary && is_file($this->path)) {
            @unlink($this->path);
        }
    }

    /**
     * Safe to show an administrator: identity and shape, never the location.
     *
     * @return array{original_name: string, extension: string, size: int, declared_mime: string|null, checksum_sha256: string}
     */
    public function describe(): array
    {
        return [
            'original_name' => $this->originalName,
            'extension' => $this->extension(),
            'size' => $this->size(),
            'declared_mime' => $this->declaredMime,
            'checksum_sha256' => $this->checksum(),
        ];
    }
}
