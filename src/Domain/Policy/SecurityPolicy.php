<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Policy;

/**
 * Shared surface of every policy: a name, a human label, and which pipeline
 * checks it switches on.
 */
interface SecurityPolicy
{
    public function name(): string;

    public function label(): string;

    public function wants(string $check): bool;

    /**
     * @return array<string, bool>
     */
    public function checks(): array;

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array;
}
