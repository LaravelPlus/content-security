<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Console\Commands;

use Illuminate\Console\Command;

final class InstallCommand extends Command
{
    protected $signature = 'content-security:install
        {--pages : Also publish the Vue console pages}
        {--force : Overwrite existing published files}';

    protected $description = 'Publish the content security config, migrations and (optionally) console pages.';

    public function handle(): int
    {
        $force = (bool) $this->option('force');

        $this->publish('content-security-config', $force);
        $this->publish('content-security-migrations', $force);

        if ($this->option('pages')) {
            $this->publish('content-security-pages', $force);
            $this->components->info('Run `npm run build` to compile the console.');
        }

        $this->newLine();
        // Nothing here runs migrations or edits .env. An install command
        // that changes a production database because someone typed it to
        // see what it did is not a helpful install command.
        $this->components->info('Published. Next:');
        $this->line('  1. php artisan migrate');
        $this->line('  2. Set CONTENT_SECURITY_CLAMAV_* in .env, or use the null driver in local.');
        $this->line('  3. ContentSecurity::auth(fn ($user) => $user->isAdmin()); in a service provider.');
        $this->line('  4. php artisan content-security:status');

        return self::SUCCESS;
    }

    private function publish(string $tag, bool $force): void
    {
        $this->call('vendor:publish', array_filter([
            '--tag' => $tag,
            '--force' => $force ?: null,
        ]));
    }
}
