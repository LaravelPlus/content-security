<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\ServiceProvider;
use Inertia\Inertia;
use LaravelPlus\ContentSecurity\Console\Commands\CleanupQuarantineCommand;
use LaravelPlus\ContentSecurity\Console\Commands\HealthCommand;
use LaravelPlus\ContentSecurity\Console\Commands\InstallCommand;
use LaravelPlus\ContentSecurity\Console\Commands\PublishPagesCommand;
use LaravelPlus\ContentSecurity\Console\Commands\ReportCommand;
use LaravelPlus\ContentSecurity\Console\Commands\ScanCommand;
use LaravelPlus\ContentSecurity\Console\Commands\StatusCommand;
use LaravelPlus\ContentSecurity\Contracts\ArchiveInspector as ArchiveInspectorContract;
use LaravelPlus\ContentSecurity\Contracts\FileCheck;
use LaravelPlus\ContentSecurity\Contracts\ImageInspector as ImageInspectorContract;
use LaravelPlus\ContentSecurity\Contracts\PdfInspector as PdfInspectorContract;
use LaravelPlus\ContentSecurity\Contracts\PolicyRepository;
use LaravelPlus\ContentSecurity\Contracts\Sanitizer;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Contracts\TextCheck;
use LaravelPlus\ContentSecurity\Contracts\TextInspector;
use LaravelPlus\ContentSecurity\Contracts\UrlInspector;
use LaravelPlus\ContentSecurity\File\Archives\ArchiveInspector;
use LaravelPlus\ContentSecurity\File\Archives\ArchiveLimits;
use LaravelPlus\ContentSecurity\File\Checks\ArchiveCheck;
use LaravelPlus\ContentSecurity\File\Checks\ExtensionCheck;
use LaravelPlus\ContentSecurity\File\Checks\ImageCheck;
use LaravelPlus\ContentSecurity\File\Checks\MagicBytesCheck;
use LaravelPlus\ContentSecurity\File\Checks\MalwareCheck;
use LaravelPlus\ContentSecurity\File\Checks\MimeCheck;
use LaravelPlus\ContentSecurity\File\Checks\PdfCheck;
use LaravelPlus\ContentSecurity\File\Checks\SizeCheck;
use LaravelPlus\ContentSecurity\File\Images\ImageInspector;
use LaravelPlus\ContentSecurity\File\Malware\MalwareScannerManager;
use LaravelPlus\ContentSecurity\File\Pdf\PdfInspector;
use LaravelPlus\ContentSecurity\Listeners\LogSecurityEvent;
use LaravelPlus\ContentSecurity\Pipeline\CheckRegistry;
use LaravelPlus\ContentSecurity\Pipeline\PipelineRunner;
use LaravelPlus\ContentSecurity\Repositories\ConfigPolicyRepository;
use LaravelPlus\ContentSecurity\Repositories\DatabasePolicyRepository;
use LaravelPlus\ContentSecurity\Repositories\EloquentScanRepository;
use LaravelPlus\ContentSecurity\Repositories\NullScanRepository;
use LaravelPlus\ContentSecurity\Support\HookRegistry;
use LaravelPlus\ContentSecurity\Support\MimeTypes;
use LaravelPlus\ContentSecurity\Text\Checks\HtmlCheck;
use LaravelPlus\ContentSecurity\Text\Checks\LengthCheck;
use LaravelPlus\ContentSecurity\Text\Checks\SuspiciousContentCheck;
use LaravelPlus\ContentSecurity\Text\Checks\UrlsCheck;
use LaravelPlus\ContentSecurity\Text\Html\HtmlSanitizer;
use LaravelPlus\ContentSecurity\Text\SuspiciousContent\SuspiciousContentScanner;
use LaravelPlus\ContentSecurity\Text\Url\UrlScanner;

final class ContentSecurityServiceProvider extends ServiceProvider
{
    /**
     * The shipped file pipeline, cheapest first. The malware engine is last
     * because it is the only step that costs a network round trip and a full
     * read of the file.
     *
     * @var list<class-string<FileCheck>>
     */
    private const FILE_CHECKS = [
        SizeCheck::class,
        ExtensionCheck::class,
        MimeCheck::class,
        MagicBytesCheck::class,
        ArchiveCheck::class,
        ImageCheck::class,
        PdfCheck::class,
        MalwareCheck::class,
    ];

    /**
     * Sanitize before pattern-matching.
     *
     * The order matters for a reason worth stating: SuspiciousContentCheck
     * reports `<script>` as a High finding, which ends the run. With it
     * ahead of HtmlCheck, the sanitizer never ran on precisely the input
     * that needed sanitizing — and SafeHtml::sanitized() came back null on
     * every document that actually contained markup to strip.
     *
     * @var list<class-string<TextCheck>>
     */
    private const TEXT_CHECKS = [
        LengthCheck::class,
        HtmlCheck::class,
        SuspiciousContentCheck::class,
        UrlsCheck::class,
    ];

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/content-security.php', 'content-security');

        $this->registerCollaborators();
        $this->registerRegistries();
        $this->registerRepository();
        $this->registerPolicyRepository();

        $this->app->singleton(ContentSecurity::class);
    }

    public function boot(): void
    {
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'content-security');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'content-security');

        if ((bool) config('content-security.persistence.enabled', true)) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }

        $this->registerPublishing();
        $this->registerCommands();
        $this->registerSchedule();

        $this->app->make('events')->subscribe(LogSecurityEvent::class);

        // Policies resolve through the repository unless the host has
        // registered its own resolver, which still wins.
        $security = $this->app->make(ContentSecurity::class);
        $policies = $this->app->make(PolicyRepository::class);

        $security->resolveFilePolicyUsing($policies->file(...));
        $security->resolveTextPolicyUsing($policies->text(...));

        if ((bool) config('content-security.admin.enabled', true)) {
            $this->registerConsole();
        }
    }

    // -----------------------------------------------------------------
    // Bindings
    // -----------------------------------------------------------------

    /**
     * Every collaborator is bound to its contract, so a host can replace any
     * one of them from its own service provider without forking the package.
     */
    private function registerCollaborators(): void
    {
        $this->app->singleton(MimeTypes::class);
        $this->app->singleton(HookRegistry::class);

        $this->app->singleton(PipelineRunner::class, static fn (): PipelineRunner => PipelineRunner::fromConfig());

        $this->app->singleton(
            MalwareScannerManager::class,
            static fn (Container $app): MalwareScannerManager => new MalwareScannerManager($app),
        );

        $this->app->singleton(
            Sanitizer::class,
            static fn (): Sanitizer => HtmlSanitizer::fromConfig(),
        );

        $this->app->singleton(
            ArchiveInspectorContract::class,
            static fn (): ArchiveInspectorContract => new ArchiveInspector(ArchiveLimits::fromConfig()),
        );

        $this->app->singleton(
            ImageInspectorContract::class,
            static fn (): ImageInspectorContract => ImageInspector::fromConfig(),
        );

        $this->app->singleton(
            PdfInspectorContract::class,
            static fn (): PdfInspectorContract => PdfInspector::fromConfig(),
        );

        $this->app->singleton(
            TextInspector::class,
            static fn (): TextInspector => new SuspiciousContentScanner,
        );

        $this->app->singleton(
            UrlInspector::class,
            static fn (): UrlInspector => UrlScanner::fromConfig(),
        );
    }

    private function registerRegistries(): void
    {
        $this->app->singleton(CheckRegistry::class, static function (Container $app): CheckRegistry {
            $registry = new CheckRegistry($app);
            $registry->setFileChecks(self::FILE_CHECKS);
            $registry->setTextChecks(self::TEXT_CHECKS);

            return $registry;
        });
    }

    private function registerRepository(): void
    {
        $this->app->singleton(ScanRepository::class, static fn (): ScanRepository => (bool) config('content-security.persistence.enabled', true)
            ? new EloquentScanRepository
            : new NullScanRepository);
    }

    /**
     * Config is the baseline in both cases. The database implementation adds
     * a layer of runtime overrides on top of it; the config one has no layer
     * at all.
     */
    private function registerPolicyRepository(): void
    {
        $this->app->singleton(PolicyRepository::class, static function (Container $app): PolicyRepository {
            $editable = (bool) config('content-security.admin.manage_policies', true)
                && (bool) config('content-security.persistence.enabled', true);

            return $editable
                ? new DatabasePolicyRepository($app->make('events'))
                : new ConfigPolicyRepository;
        });
    }

    // -----------------------------------------------------------------
    // Boot
    // -----------------------------------------------------------------

    private function registerPublishing(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__.'/../config/content-security.php' => config_path('content-security.php'),
        ], 'content-security-config');

        $this->publishes([
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ], 'content-security-migrations');

        // The console is published into the host's own page tree, because
        // that is where its Vite build looks for Inertia pages.
        $this->publishes([
            __DIR__.'/../resources/js/pages' => resource_path('js/pages/admin/content-security'),
        ], 'content-security-pages');

        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/content-security'),
        ], 'content-security-views');

        $this->publishes([
            __DIR__.'/../lang' => lang_path('vendor/content-security'),
        ], 'content-security-lang');
    }

    private function registerCommands(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->commands([
            StatusCommand::class,
            ScanCommand::class,
            HealthCommand::class,
            CleanupQuarantineCommand::class,
            ReportCommand::class,
            InstallCommand::class,
            PublishPagesCommand::class,
        ]);
    }

    /**
     * Registered whatever the SAPI. `callAfterResolving` only fires when
     * something resolves the Schedule, and a console page that lists what is
     * scheduled resolves it in a browser — behind runningInConsole() those
     * rows would be invisible to every web request.
     */
    private function registerSchedule(): void
    {
        $timezone = (string) config('content-security.reports.timezone', config('app.timezone', 'UTC'));

        if ((bool) config('content-security.reports.daily.enabled', true)) {
            $this->callAfterResolving(Schedule::class, static function (Schedule $schedule) use ($timezone): void {
                $schedule->command('content-security:report --period=daily')
                    ->dailyAt((string) config('content-security.reports.daily.at', '07:30'))
                    ->timezone($timezone)
                    ->name('content-security:report:daily')
                    ->onOneServer()
                    ->withoutOverlapping();
            });
        }

        if ((bool) config('content-security.reports.weekly.enabled', true)) {
            $this->callAfterResolving(Schedule::class, static function (Schedule $schedule) use ($timezone): void {
                $schedule->command('content-security:report --period=weekly')
                    ->weeklyOn(
                        self::dayOfWeek((string) config('content-security.reports.weekly.day', 'monday')),
                        (string) config('content-security.reports.weekly.at', '08:00'),
                    )
                    ->timezone($timezone)
                    ->name('content-security:report:weekly')
                    ->onOneServer()
                    ->withoutOverlapping();
            });
        }

        if ((bool) config('content-security.schedule.cleanup_quarantine', true)) {
            $this->callAfterResolving(Schedule::class, static function (Schedule $schedule) use ($timezone): void {
                $schedule->command('content-security:cleanup-quarantine --force --prune-scans')
                    ->dailyAt((string) config('content-security.schedule.cleanup_at', '03:30'))
                    ->timezone($timezone)
                    ->name('content-security:cleanup-quarantine')
                    ->onOneServer()
                    ->withoutOverlapping();
            });
        }
    }

    private function registerConsole(): void
    {
        $this->loadRoutesFrom(__DIR__.'/../routes/web.php');

        if (! class_exists(Inertia::class)) {
            return;
        }

        Inertia::share('contentSecurity', static fn (): array => [
            'basePath' => '/'.trim((string) config('content-security.admin.prefix', 'admin/content-security'), '/'),
            'brand' => (string) config('content-security.admin.brand.title', 'Content Security'),
            'backUrl' => (string) config('content-security.admin.brand.back_url', '/'),
            'backLabel' => (string) config('content-security.admin.brand.back_label', 'Back'),
            'exposePaths' => (bool) config('content-security.admin.expose_paths', false),
        ]);
    }

    private static function dayOfWeek(string $day): int
    {
        return match (mb_strtolower($day)) {
            'sunday' => 0,
            'tuesday' => 2,
            'wednesday' => 3,
            'thursday' => 4,
            'friday' => 5,
            'saturday' => 6,
            default => 1,
        };
    }
}
