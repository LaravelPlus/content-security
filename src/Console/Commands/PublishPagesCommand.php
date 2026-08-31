<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Console\Commands;

use Illuminate\Console\Command;

final class PublishPagesCommand extends Command
{
    protected $signature = 'content-security:publish-pages {--force : Overwrite existing files}';

    protected $description = 'Publish the Vue console into resources/js/pages/admin/content-security.';

    public function handle(): int
    {
        $this->call('vendor:publish', array_filter([
            '--tag' => 'content-security-pages',
            '--force' => $this->option('force') ?: null,
        ]));

        $this->components->info('Console pages published. Run `npm run build` (or `npm run dev`) to compile.');

        return self::SUCCESS;
    }
}
