<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Filesystem\Factory as FilesystemFactory;
use LaravelPlus\ContentSecurity\ContentSecurity;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Pipeline\CheckRegistry;

/**
 * The "is this actually configured correctly?" command. Run it after
 * installing, and in a deployment smoke test.
 */
final class StatusCommand extends Command
{
    protected $signature = 'content-security:status';

    protected $description = 'Show the content security configuration, scanner state and recent activity.';

    public function handle(
        ContentSecurity $security,
        ScanRepository $repository,
        CheckRegistry $checks,
        FilesystemFactory $filesystem,
    ): int {
        $enabled = (bool) config('content-security.enabled', true);
        $failClosed = (bool) config('content-security.fail_closed', true);

        $this->components->twoColumnDetail('Enabled', $enabled ? '<fg=green>yes</>' : '<fg=red>no</>');
        $this->components->twoColumnDetail('Fail closed', $failClosed ? '<fg=green>yes</>' : '<fg=yellow>no</>');
        $this->components->twoColumnDetail('Malware driver', (string) config('content-security.malware.default'));
        $this->components->twoColumnDetail('Persistence', config('content-security.persistence.enabled') ? 'on' : 'off');
        $this->components->twoColumnDetail('Admin console', config('content-security.admin.enabled') ? '/'.config('content-security.admin.prefix') : 'disabled');

        $this->newLine();
        $this->components->info('Scanners');

        foreach ($security->health() as $health) {
            $this->components->twoColumnDetail(
                $health->scanner.($health->connection !== null ? ' <fg=gray>('.$health->connection.')</>' : ''),
                match ($health->status()) {
                    'online' => '<fg=green>online</> '.($health->version ?? ''),
                    'disabled' => '<fg=gray>disabled</>',
                    default => '<fg=red>offline</> '.($health->error ?? ''),
                },
            );
        }

        $this->newLine();
        $this->components->info('Pipeline');
        $this->line('  Files: '.implode(' → ', array_map(
            static fn (object $check): string => $check->key(),
            $checks->fileChecks(),
        )));
        $this->line('  Text:  '.implode(' → ', array_map(
            static fn (object $check): string => $check->key(),
            $checks->textChecks(),
        )));

        $this->newLine();
        $this->components->info('Last 24 hours');

        foreach ($repository->statistics(24) as $key => $value) {
            $this->components->twoColumnDetail(str_replace('_', ' ', (string) $key), (string) $value);
        }

        $this->newLine();

        return $this->warnAboutRisks($failClosed, $enabled, $filesystem);
    }

    private function warnAboutRisks(bool $failClosed, bool $enabled, FilesystemFactory $filesystem): int
    {
        $warnings = 0;

        if (! $enabled) {
            $this->components->warn('Scanning is disabled — every validation rule is passing everything through.');
            $warnings++;
        }

        if (! $failClosed) {
            $this->components->warn('fail_closed is off. A scanner outage will let unscanned files through as clean.');
            $warnings++;
        }

        if (config('content-security.malware.default') === 'null') {
            $this->components->warn('The null malware driver is active. No signature scanning is happening.');
            $warnings++;
        }

        // A quarantine disk that is web-served turns the quarantine into a
        // malware distribution endpoint, which is worth shouting about.
        $disk = (string) config('content-security.storage.quarantine_disk', 'local');

        if (in_array($disk, ['public', 's3-public'], true)) {
            $this->components->error(sprintf(
                'The quarantine disk [%s] looks publicly served. Quarantined files must not be reachable over HTTP.',
                $disk,
            ));
            $warnings++;
        }

        if ($warnings === 0) {
            $this->components->info('No configuration warnings.');
        }

        return self::SUCCESS;
    }
}
