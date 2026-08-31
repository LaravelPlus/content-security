<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;

/**
 * Where policies come from.
 *
 * The shipped implementation layers database overrides on top of the config
 * file. A host that wants per-tenant policies, or policies from an entirely
 * different store, binds its own here — or uses
 * ContentSecurity::resolveFilePolicyUsing() for a closure-sized version.
 */
interface PolicyRepository
{
    public function file(string $name): FilePolicy;

    public function text(string $name): TextPolicy;

    /**
     * @return list<FilePolicy>
     */
    public function allFile(): array;

    /**
     * @return list<TextPolicy>
     */
    public function allText(): array;

    /** Whether this policy currently differs from the config baseline. */
    public function isOverridden(string $type, string $name): bool;

    /**
     * @param  array<string, mixed>  $settings
     */
    public function override(string $type, string $name, array $settings, int|string|null $actorId = null, ?string $note = null): void;

    /** Drops the override and returns the policy to its config baseline. */
    public function reset(string $type, string $name): void;
}
