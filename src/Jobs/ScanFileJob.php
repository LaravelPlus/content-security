<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use LaravelPlus\ContentSecurity\Actions\ScanFile;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use Throwable;

/**
 * Scans a file that is already sitting in quarantine storage.
 *
 * Two things make this safe to retry. The scan id is fixed by the caller, so
 * the audit row is updated rather than duplicated on a second attempt; and
 * the file is addressed by disk and path, so nothing large is serialised
 * into the queue payload.
 */
final class ScanFileJob implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public function __construct(
        public readonly ScanId $scanId,
        public readonly string $disk,
        public readonly string $path,
        public readonly string $originalName,
        public readonly ?string $policy = null,
    ) {
        $this->onConnection(config('content-security.queue.connection'));
        $this->onQueue((string) config('content-security.queue.queue', 'default'));
    }

    public function tries(): int
    {
        return (int) config('content-security.queue.tries', 3);
    }

    public function timeout(): int
    {
        return (int) config('content-security.queue.timeout', 300);
    }

    /**
     * @return list<int>
     */
    public function backoff(): array
    {
        /** @var list<int> $backoff */
        $backoff = (array) config('content-security.queue.backoff', [10, 60, 300]);

        return $backoff;
    }

    /** One scan per id at a time, whatever the retry story. */
    public function uniqueId(): string
    {
        return (string) $this->scanId;
    }

    public function handle(ScanFile $scanFile, ScanRepository $repository): void
    {
        $repository->markScanning($this->scanId);

        $file = FileReference::fromDisk($this->disk, $this->path, $this->originalName);

        try {
            // The file is already in quarantine; re-quarantining it would
            // write a second copy. The verdict alone is what changes here.
            $scanFile->handle($file, $this->policy, $this->scanId, quarantineOnThreat: false);
        } finally {
            $file->discardTemporary();
        }
    }

    /**
     * Every retry is exhausted. The row must not be left saying "scanning"
     * for ever — an unfinished scan is a failed scan, and fail-closed means
     * the application must be able to see that.
     */
    public function failed(?Throwable $exception): void
    {
        app(ScanRepository::class)->markStatus($this->scanId, ScanStatus::Failed);
    }
}
