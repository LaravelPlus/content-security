<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Filesystem\Factory as FilesystemFactory;
use Illuminate\Support\Str;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Events\FileQuarantined;
use LaravelPlus\ContentSecurity\Exceptions\QuarantineException;

/**
 * Moves a rejected file somewhere it can be examined but not served.
 *
 * Two rules hold the whole design together:
 *
 *  1. The stored name is a ULID this package generates. The uploader's
 *     filename never touches the path — it is the input that carries
 *     traversal sequences, null bytes and executable extensions, and it is
 *     kept as metadata where it can be read but not obeyed.
 *  2. The quarantine disk must not be web-served. The package cannot
 *     enforce that; the README says it, and `content-security:status` warns
 *     when the configured disk looks public.
 */
final readonly class QuarantineFile
{
    public function __construct(
        private FilesystemFactory $filesystem,
        private ScanRepository $repository,
        private Dispatcher $events,
    ) {}

    public function handle(FileReference $file, ScanId $scanId, ?ScanResult $result = null): string
    {
        $disk = (string) config('content-security.storage.quarantine_disk', 'local');
        $directory = trim((string) config('content-security.storage.quarantine_path', 'content-security/quarantine'), '/');

        // Extension preserved only as a suffix on a generated name, so the
        // stored object is still recognisable to an operator without the
        // path ever being uploader-controlled.
        $extension = $file->extension();
        $name = (string) Str::ulid();
        $path = $directory.'/'.$name.($extension !== '' ? '.'.$extension.'.quarantined' : '.quarantined');

        $stream = $file->stream();

        try {
            $stored = $this->filesystem->disk($disk)->writeStream($path, $stream);
        } finally {
            if (is_resource($stream)) {
                fclose($stream);
            }
        }

        if ($stored === false) {
            throw QuarantineException::writeFailed($disk, $path);
        }

        $this->repository->recordQuarantine($scanId, [
            'quarantine_disk' => $disk,
            'quarantine_path' => $path,
            'original_filename' => $file->originalName,
            'checksum_sha256' => $file->checksum(),
        ]);

        $this->events->dispatch(new FileQuarantined($scanId, $disk, $path, $result));

        return $path;
    }
}
