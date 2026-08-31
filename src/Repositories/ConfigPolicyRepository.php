<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Repositories;

use LaravelPlus\ContentSecurity\Contracts\PolicyRepository;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;

/**
 * Config only — no database, no runtime editing.
 *
 * Bound when `admin.manage_policies` is off, and the right choice for an
 * installation that wants its security policy to be reviewable in a diff
 * and nowhere else.
 */
final class ConfigPolicyRepository implements PolicyRepository
{
    public function file(string $name): FilePolicy
    {
        return FilePolicy::named($name);
    }

    public function text(string $name): TextPolicy
    {
        return TextPolicy::named($name);
    }

    /**
     * @return list<FilePolicy>
     */
    public function allFile(): array
    {
        /** @var array<string, mixed> $policies */
        $policies = (array) config('content-security.files.policies', []);

        return array_values(array_map(
            static fn (string $name): FilePolicy => FilePolicy::named($name),
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
            static fn (string $name): TextPolicy => TextPolicy::named($name),
            array_map(strval(...), array_keys($policies)),
        ));
    }

    public function isOverridden(string $type, string $name): bool
    {
        return false;
    }

    /**
     * @param  array<string, mixed>  $settings
     */
    public function override(string $type, string $name, array $settings = [], int|string|null $actorId = null, ?string $note = null): void
    {
        // Intentionally inert. Editing is off; the console renders read-only.
    }

    public function reset(string $type, string $name): void
    {
        // Nothing to reset — config is already the only source.
    }
}
