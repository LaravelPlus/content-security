<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Console\Commands;

use Illuminate\Console\Command;
use LaravelPlus\ContentSecurity\ContentSecurity;
use LaravelPlus\ContentSecurity\Support\ScannerHealth;

final class HealthCommand extends Command
{
    protected $signature = 'content-security:health {--json}';

    protected $description = 'Check that every configured scanner is reachable.';

    public function handle(ContentSecurity $security): int
    {
        $health = $security->health();

        if ($this->option('json')) {
            $this->line((string) json_encode(
                array_map(static fn (ScannerHealth $h): array => $h->toArray(), $health),
                JSON_PRETTY_PRINT,
            ));
        } else {
            $this->table(
                ['Scanner', 'Status', 'Version', 'Signatures', 'Ping', 'Connection'],
                array_map(static fn (ScannerHealth $h): array => [
                    $h->scanner,
                    $h->status(),
                    $h->version ?? '—',
                    $h->signaturesUpdatedAt?->format('Y-m-d H:i') ?? '—',
                    $h->pingMs === null ? '—' : sprintf('%.0f ms', $h->pingMs),
                    $h->connection ?? '—',
                ], $health),
            );
        }

        // Non-zero when an *enabled* scanner is down, so this works as a
        // health probe. A driver deliberately disabled is not a failure.
        foreach ($health as $scanner) {
            if ($scanner->enabled && ! $scanner->online) {
                return self::FAILURE;
            }
        }

        return self::SUCCESS;
    }
}
