<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Filesystem\Factory as FilesystemFactory;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Models\SecurityScan;
use Throwable;

final class CleanupQuarantineCommand extends Command
{
    protected $signature = 'content-security:cleanup-quarantine
        {--days= : Delete quarantined files older than this many days}
        {--prune-scans : Also prune scan history past its retention window}
        {--force : Skip the confirmation prompt}';

    protected $description = 'Delete expired quarantined files and, optionally, old scan history.';

    public function handle(FilesystemFactory $filesystem, ScanRepository $repository): int
    {
        $days = (int) ($this->option('days') ?? config('content-security.storage.retention_days', 30));
        $cutoff = now()->subDays($days);

        $expired = SecurityScan::query()
            ->quarantined()
            ->where('created_at', '<', $cutoff)
            ->get();

        if ($expired->isEmpty()) {
            $this->components->info(sprintf('No quarantined files older than %d days.', $days));
        } else {
            // Deleting evidence is irreversible, so it is confirmed unless
            // the caller is a scheduler that passed --force.
            if (! $this->option('force') && ! $this->confirm(
                sprintf('Permanently delete %d quarantined file(s) older than %d days?', $expired->count(), $days),
            )) {
                $this->components->warn('Aborted.');

                return self::FAILURE;
            }

            $deleted = 0;

            foreach ($expired as $scan) {
                try {
                    $filesystem->disk((string) $scan->quarantine_disk)->delete((string) $scan->quarantine_path);
                } catch (Throwable $e) {
                    $this->components->warn(sprintf('%s: %s', $scan->scan_id, $e->getMessage()));

                    continue;
                }

                // The row stays. The audit trail outlives the artefact —
                // that a file was quarantined is the part worth keeping.
                $scan->forceFill(['quarantine_disk' => null, 'quarantine_path' => null])->save();
                $deleted++;
            }

            $this->components->info(sprintf('Deleted %d quarantined file(s).', $deleted));
        }

        if ($this->option('prune-scans')) {
            $retention = (int) config('content-security.persistence.prune_after_days', 180);
            $pruned = $repository->prune($retention);
            $this->components->info(sprintf('Pruned %d scan record(s) older than %d days.', $pruned, $retention));
        }

        return self::SUCCESS;
    }
}
