<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Filesystem\Factory as FilesystemFactory;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Events\QuarantineDeleted;
use LaravelPlus\ContentSecurity\Events\QuarantineReleased;
use LaravelPlus\ContentSecurity\Exceptions\QuarantineException;
use LaravelPlus\ContentSecurity\Models\SecurityScan;
use Throwable;

/**
 * Letting a file back out is the one operation here that can undo every
 * other control in the package, so it has its own rules:
 *
 *  - the file is rescanned first, and a release proceeds only on a clean
 *    result;
 *  - an override is possible, must be asked for explicitly, and is
 *    dispatched as an audited event;
 *  - the release target is chosen by the application, never by anything
 *    recorded from the upload.
 */
final readonly class ReleaseQuarantinedFile
{
    public function __construct(
        private FilesystemFactory $filesystem,
        private ScanRepository $repository,
        private ScanFile $scanFile,
        private Dispatcher $events,
    ) {}

    public function handle(
        SecurityScan $scan,
        string $targetDisk,
        string $targetPath,
        int|string|null $actorId = null,
        bool $override = false,
    ): void {
        if (! $scan->isQuarantined()) {
            throw QuarantineException::notQuarantined($scan->scan_id);
        }

        $disk = (string) $scan->quarantine_disk;
        $path = (string) $scan->quarantine_path;

        if (! $this->filesystem->disk($disk)->exists($path)) {
            throw QuarantineException::missingFile($path);
        }

        $file = FileReference::fromDisk($disk, $path, $scan->original_filename ?? 'quarantined');

        try {
            $rescan = $this->scanFile->handle($file, $scan->policy, quarantineOnThreat: false);

            if (! $rescan->isClean() && ! $override) {
                throw QuarantineException::releaseRequiresCleanScan($scan->scan_id);
            }

            $stream = $file->stream();

            try {
                $stored = $this->filesystem->disk($targetDisk)->writeStream($targetPath, $stream);
            } finally {
                if (is_resource($stream)) {
                    fclose($stream);
                }
            }

            if ($stored === false) {
                throw QuarantineException::writeFailed($targetDisk, $targetPath);
            }
        } finally {
            $file->discardTemporary();
        }

        $this->filesystem->disk($disk)->delete($path);

        $scan->forceFill([
            'status' => ScanStatus::Clean->value,
            'quarantine_disk' => null,
            'quarantine_path' => null,
        ])->save();

        $this->events->dispatch(new QuarantineReleased(
            scanId: ScanId::fromString($scan->scan_id),
            targetDisk: $targetDisk,
            targetPath: $targetPath,
            actorId: $actorId,
            overridden: $override,
        ));
    }

    /** Permanent deletion of the quarantined object. The row is kept. */
    public function delete(SecurityScan $scan, int|string|null $actorId = null): void
    {
        if (! $scan->isQuarantined()) {
            throw QuarantineException::notQuarantined($scan->scan_id);
        }

        try {
            $this->filesystem->disk((string) $scan->quarantine_disk)->delete((string) $scan->quarantine_path);
        } catch (Throwable) {
            // An object already gone from the disk is the desired end state.
        }

        $scan->forceFill([
            'quarantine_disk' => null,
            'quarantine_path' => null,
        ])->save();

        $this->events->dispatch(new QuarantineDeleted(ScanId::fromString($scan->scan_id), $actorId));
    }

    /** Rescan without releasing — the console's "Rescan" button. */
    public function rescan(SecurityScan $scan): void
    {
        if (! $scan->isQuarantined()) {
            throw QuarantineException::notQuarantined($scan->scan_id);
        }

        $file = FileReference::fromDisk(
            (string) $scan->quarantine_disk,
            (string) $scan->quarantine_path,
            $scan->original_filename ?? 'quarantined',
        );

        try {
            $result = $this->scanFile->handle($file, $scan->policy, quarantineOnThreat: false);
        } finally {
            $file->discardTemporary();
        }

        // The object stays in quarantine either way; only the verdict moves,
        // so an operator can see that a rescan now comes back clean without
        // the file having been let out by the act of checking.
        $this->repository->markStatus(
            ScanId::fromString($scan->scan_id),
            $result->isClean() ? ScanStatus::Quarantined : $result->status(),
        );
    }
}
