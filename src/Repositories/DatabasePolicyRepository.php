<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Repositories;

use Illuminate\Contracts\Events\Dispatcher;
use LaravelPlus\ContentSecurity\Contracts\PolicyRepository;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Events\PolicyChanged;
use LaravelPlus\ContentSecurity\Exceptions\PolicyNotFoundException;
use LaravelPlus\ContentSecurity\Models\SecurityPolicySetting;
use Throwable;

/**
 * Config is the baseline; the database holds overrides on top of it.
 *
 * That layering is the whole design. A policy the operator has never touched
 * has no row at all and reads straight from `config/content-security.php`,
 * so a deployment's defaults stay the reviewed, version-controlled thing
 * they should be. A row records only the fields someone actually changed,
 * which is what makes "reset to config" meaningful and what keeps a config
 * change (say, tightening the default max size in a release) visible to
 * every policy that has not deliberately overridden it.
 *
 * Two things are never overridable from the database, and both are
 * enforced below rather than in the UI:
 *
 *  - `forbidden_extensions`, the list of server-executable formats. If a
 *    console could add `php` to an allowlist, the console would be the
 *    vulnerability.
 *  - the hard ceiling on `max_size`, so a stray edit cannot turn the upload
 *    endpoint into a disk-filling primitive.
 */
final readonly class DatabasePolicyRepository implements PolicyRepository
{
    /** Keys an override may set. Anything else is ignored. */
    private const FILE_KEYS = ['label', 'max_size', 'extensions', 'mime_types', 'checks', 'on_threat'];

    private const TEXT_KEYS = ['label', 'max_length', 'checks'];

    public function __construct(private Dispatcher $events) {}

    public function file(string $name): FilePolicy
    {
        /** @var array<string, array<string, mixed>> $policies */
        $policies = (array) config('content-security.files.policies', []);

        if (! isset($policies[$name])) {
            throw PolicyNotFoundException::file($name, array_keys($policies));
        }

        /** @var list<string> $forbidden */
        $forbidden = (array) config('content-security.files.forbidden_extensions', []);

        $config = $policies[$name];
        $override = $this->readOverride('file', $name);

        if ($override !== []) {
            $config = $this->merge($config, $override, self::FILE_KEYS);
            $config['max_size'] = min(
                (int) $config['max_size'],
                (int) config('content-security.files.max_size_ceiling', 512 * 1024 * 1024),
            );
        }

        // Applied after the merge, always: an override cannot widen this.
        $config['extensions'] = array_values(array_diff(
            array_map(static fn (string $e): string => mb_strtolower(ltrim($e, '.')), (array) ($config['extensions'] ?? [])),
            array_map(static fn (string $e): string => mb_strtolower(ltrim($e, '.')), $forbidden),
        ));

        return FilePolicy::fromConfig($name, $config, $forbidden);
    }

    public function text(string $name): TextPolicy
    {
        /** @var array<string, array<string, mixed>> $policies */
        $policies = (array) config('content-security.text.policies', []);

        if (! isset($policies[$name])) {
            throw PolicyNotFoundException::text($name, array_keys($policies));
        }

        $config = $policies[$name];
        $override = $this->readOverride('text', $name);

        if ($override !== []) {
            $config = $this->merge($config, $override, self::TEXT_KEYS);
        }

        return TextPolicy::fromConfig($name, $config);
    }

    /**
     * @return list<FilePolicy>
     */
    public function allFile(): array
    {
        /** @var array<string, mixed> $policies */
        $policies = (array) config('content-security.files.policies', []);

        return array_values(array_map(
            fn (string $name): FilePolicy => $this->file($name),
            array_map(strval(...), array_keys($policies)),
        ));
    }

    /**
     * @return list<TextPolicy>
     */
    public function allText(): array
    {
        /** @var array<string, mixed> $policies */
        $policies = (array) config('content-security.text.policies', []);

        return array_values(array_map(
            fn (string $name): TextPolicy => $this->text($name),
            array_map(strval(...), array_keys($policies)),
        ));
    }

    public function isOverridden(string $type, string $name): bool
    {
        return $this->readOverride($type, $name) !== [];
    }

    /**
     * @param  array<string, mixed>  $settings
     */
    public function override(
        string $type,
        string $name,
        array $settings = [],
        int|string|null $actorId = null,
        ?string $note = null,
    ): void {
        if ($settings === []) {
            $this->reset($type, $name);

            return;
        }

        $allowed = $type === 'file' ? self::FILE_KEYS : self::TEXT_KEYS;
        $filtered = array_intersect_key($settings, array_flip($allowed));

        $before = $this->readOverride($type, $name);

        SecurityPolicySetting::query()->updateOrCreate(
            ['type' => $type, 'name' => $name],
            [
                'settings' => $filtered,
                'updated_by' => $actorId === null ? null : (string) $actorId,
                'note' => $note,
                'enabled' => true,
            ],
        );

        $this->events->dispatch(new PolicyChanged($type, $name, $before, $filtered, $actorId, $note));
    }

    public function reset(string $type, string $name): void
    {
        $before = $this->readOverride($type, $name);

        SecurityPolicySetting::query()
            ->where('type', $type)
            ->where('name', $name)
            ->delete();

        if ($before !== []) {
            $this->events->dispatch(new PolicyChanged($type, $name, $before, [], null, 'Reset to config baseline.'));
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function readOverride(string $type, string $name): array
    {
        try {
            $record = SecurityPolicySetting::query()
                ->where('type', $type)
                ->where('name', $name)
                ->where('enabled', true)
                ->first();
        } catch (Throwable) {
            // The table may not exist yet (package installed, migrations not
            // run). Falling back to config is the correct answer, not a 500
            // on every upload.
            return [];
        }

        return $record === null ? [] : $record->settings;
    }

    /**
     * @param  array<string, mixed>  $config
     * @param  array<string, mixed>  $override
     * @param  list<string>  $allowed
     * @return array<string, mixed>
     */
    private function merge(array $config, array $override, array $allowed): array
    {
        foreach ($allowed as $key) {
            if (! array_key_exists($key, $override)) {
                continue;
            }

            // `checks` merges key by key, so a config release that adds a new
            // check ships it enabled rather than having it silently dropped
            // by an override written before the check existed.
            $config[$key] = $key === 'checks' && is_array($override[$key])
                ? [...(array) ($config[$key] ?? []), ...$override[$key]]
                : $override[$key];
        }

        return $config;
    }
}
