<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Tests;

use Illuminate\Support\Facades\Schema;
use LaravelPlus\ContentSecurity\ContentSecurityServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        // A minimal users table so the console tests have something to
        // authenticate as. The package itself never touches it.
        if (! Schema::hasTable('users')) {
            Schema::create('users', function ($table): void {
                $table->id();
                $table->string('name')->nullable();
                $table->string('email')->nullable();
                $table->timestamps();
            });
        }
    }

    /**
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [ContentSecurityServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // No real engine in the unit suite: the tests that care about
        // malware use FakeMalwareScanner, and the rest must not depend on
        // whether the machine happens to have clamd installed.
        $app['config']->set('content-security.malware.default', 'none');
        $app['config']->set('filesystems.disks.quarantine', [
            'driver' => 'local',
            'root' => storage_path('framework/testing/quarantine'),
        ]);
        $app['config']->set('content-security.storage.quarantine_disk', 'quarantine');

        // Routes bind their middleware when the provider boots, so this has
        // to be set here rather than in a beforeEach. Dropping `auth` lets
        // the guest case reach the package's own Authorize middleware —
        // which is the thing under test — instead of Laravel's login
        // redirect, to a route that does not exist in a package test app.
        $app['config']->set('content-security.admin.middleware', ['web']);
    }
}
