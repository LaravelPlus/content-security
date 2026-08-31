<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use LaravelPlus\ContentSecurity\Contracts\PolicyRepository;
use LaravelPlus\ContentSecurity\Events\PolicyChanged;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Models\SecurityPolicySetting;

function policies(): PolicyRepository
{
    return app(PolicyRepository::class);
}

it('reads from config when nothing is overridden', function (): void {
    $policy = policies()->file('default');

    expect($policy->maxSize)->toBe(config('content-security.files.policies.default.max_size'))
        ->and(policies()->isOverridden('file', 'default'))->toBeFalse();
});

it('layers a database override on top of config', function (): void {
    policies()->override('file', 'default', ['max_size' => 1024 * 1024], 'tester', 'Tightened for testing');

    $policy = policies()->file('default');

    expect($policy->maxSize)->toBe(1024 * 1024)
        ->and(policies()->isOverridden('file', 'default'))->toBeTrue()
        // Untouched fields still come from config.
        ->and($policy->extensions)->toContain('pdf');
});

it('resets back to the config baseline', function (): void {
    $original = policies()->file('default')->maxSize;

    policies()->override('file', 'default', ['max_size' => 4096]);
    expect(policies()->file('default')->maxSize)->toBe(4096);

    policies()->reset('file', 'default');

    expect(policies()->file('default')->maxSize)->toBe($original)
        ->and(policies()->isOverridden('file', 'default'))->toBeFalse();
});

it('never lets an override allow a server-executable extension', function (): void {
    // The whole point of the override table having a screening layer: a
    // console that could do this would be the vulnerability.
    policies()->override('file', 'default', ['extensions' => ['pdf', 'php', 'phtml', 'jpg']]);

    $policy = policies()->file('default');

    expect($policy->extensions)->toContain('pdf')
        ->and($policy->extensions)->toContain('jpg')
        ->and($policy->extensions)->not->toContain('php')
        ->and($policy->extensions)->not->toContain('phtml')
        ->and($policy->allowsExtension('php'))->toBeFalse();
});

it('caps an override at the configured size ceiling', function (): void {
    config()->set('content-security.files.max_size_ceiling', 10 * 1024 * 1024);

    policies()->override('file', 'default', ['max_size' => 900 * 1024 * 1024]);

    expect(policies()->file('default')->maxSize)->toBe(10 * 1024 * 1024);
});

it('merges checks key by key so a newly shipped check stays on', function (): void {
    // An override written before `pdf` existed must not switch it off.
    policies()->override('file', 'default', ['checks' => ['malware' => false]]);

    $policy = policies()->file('default');

    expect($policy->wants('malware'))->toBeFalse()
        ->and($policy->wants('pdf'))->toBeTrue()
        ->and($policy->wants('extension'))->toBeTrue();
});

it('ignores keys that are not part of the policy', function (): void {
    policies()->override('file', 'default', [
        'max_size' => 2048,
        'forbidden_extensions' => [],
        'nonsense' => 'value',
    ]);

    $stored = SecurityPolicySetting::query()->where('name', 'default')->firstOrFail();

    expect($stored->settings)->toHaveKey('max_size')
        ->and($stored->settings)->not->toHaveKey('forbidden_extensions')
        ->and($stored->settings)->not->toHaveKey('nonsense');
});

it('dispatches an audited event on every change', function (): void {
    Event::fake([PolicyChanged::class]);
    // The repository is a singleton that took the dispatcher at resolve
    // time; without this it still holds the pre-fake one.
    app()->forgetInstance(PolicyRepository::class);

    policies()->override('file', 'default', ['max_size' => 2048], 'user-7', 'Reduced after an incident');

    Event::assertDispatched(PolicyChanged::class, static function (PolicyChanged $event): bool {
        return $event->name === 'default'
            && $event->actorId === 'user-7'
            && $event->after['max_size'] === 2048
            && $event->note === 'Reduced after an incident';
    });
});

it('applies an override to real scans', function (): void {
    $directory = sys_get_temp_dir().'/cs-policy-'.bin2hex(random_bytes(6));
    mkdir($directory);
    $path = $directory.'/notes.txt';
    file_put_contents($path, str_repeat('x', 5000));

    expect(ContentSecurity::scanFile($path)->isClean())->toBeTrue();

    policies()->override('file', 'default', ['max_size' => 1024]);

    // Same file, same call — the runtime policy now rejects it.
    expect(ContentSecurity::scanFile($path)->isClean())->toBeFalse();
});

it('falls back to config when runtime editing is disabled', function (): void {
    config()->set('content-security.admin.manage_policies', false);
    app()->forgetInstance(PolicyRepository::class);

    policies()->override('file', 'default', ['max_size' => 1]);

    expect(policies()->file('default')->maxSize)
        ->toBe(config('content-security.files.policies.default.max_size'));
});
