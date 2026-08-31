<?php

declare(strict_types=1);

use LaravelPlus\ContentSecurity\Actions\QuarantineFile;
use LaravelPlus\ContentSecurity\Actions\ScanFile;
use LaravelPlus\ContentSecurity\Actions\ScanText;
use LaravelPlus\ContentSecurity\Contracts\PolicyRepository;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Tests\TestCase;

uses(TestCase::class)->in('Feature', 'Unit');

/**
 * ContentSecurity and its actions are singletons that took the event
 * dispatcher at resolve time, so Event::fake() or Bus::fake() called after
 * they exist swaps a dispatcher nobody is holding. Drop them and let the
 * next call rebuild against the fake.
 */
function forgetResolvedServices(): void
{
    foreach ([
        LaravelPlus\ContentSecurity\ContentSecurity::class,
        ScanFile::class,
        ScanText::class,
        QuarantineFile::class,
        PolicyRepository::class,
    ] as $service) {
        app()->forgetInstance($service);
    }

    ContentSecurity::clearResolvedInstances();
}
