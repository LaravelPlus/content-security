<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Console\Commands;

use Illuminate\Console\Command;
use LaravelPlus\ContentSecurity\ContentSecurity;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;

final class ScanCommand extends Command
{
    protected $signature = 'content-security:scan
        {path : Path to the file to scan}
        {--policy= : The file policy to apply}
        {--json : Output the raw scan result as JSON}';

    protected $description = 'Scan a file from the command line.';

    public function handle(ContentSecurity $security): int
    {
        $path = is_string($this->argument('path')) ? $this->argument('path') : '';

        if (! is_file($path)) {
            $this->components->error(sprintf('No file at [%s].', $path));

            return self::FAILURE;
        }

        $policy = $this->option('policy');
        $result = $security->scanFile($path, is_string($policy) ? $policy : null);

        if ($this->option('json')) {
            $this->line((string) json_encode($result->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return $result->isClean() ? self::SUCCESS : self::FAILURE;
        }

        $this->components->twoColumnDetail('Scan', (string) $result->scanId());
        $this->components->twoColumnDetail('Status', $this->colour($result->status()->value));
        $this->components->twoColumnDetail('Duration', sprintf('%.1f ms', $result->duration()));

        $this->newLine();

        foreach ($result->checks() as $check) {
            $this->components->twoColumnDetail(
                $check->check.($check->skipped ? ' <fg=gray>(skipped)</>' : ''),
                $this->colour($check->status->value),
            );
        }

        if ($result->threats() !== []) {
            $this->newLine();
            $this->components->error('Findings');

            $this->table(
                ['Threat', 'Level', 'Source', 'Description'],
                array_map(static fn (Threat $threat): array => [
                    $threat->name,
                    $threat->level->value,
                    $threat->source,
                    $threat->description ?? '',
                ], $result->threats()),
            );
        }

        // Exit non-zero on anything but clean, so this is usable in a script.
        return $result->isClean() ? self::SUCCESS : self::FAILURE;
    }

    private function colour(string $status): string
    {
        return match ($status) {
            'clean' => '<fg=green>clean</>',
            'suspicious' => '<fg=yellow>suspicious</>',
            'infected' => '<fg=red>infected</>',
            'quarantined' => '<fg=red>quarantined</>',
            'failed' => '<fg=red>failed</>',
            default => $status,
        };
    }
}
