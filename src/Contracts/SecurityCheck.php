<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

/**
 * One step of a security pipeline. Steps are addressed by `key()` from the
 * policy config, so the key is part of the package's public contract.
 */
interface SecurityCheck
{
    /** Stable identifier, e.g. `mime`. Matches the policy `checks` key. */
    public function key(): string;

    /** Human label for the console. */
    public function label(): string;
}
