<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * A security policy was changed at runtime.
 *
 * Carries both sides of the change, because "the allowlist was widened" is
 * a sentence that needs a before and an after to be worth anything.
 */
final class PolicyChanged
{
    use Dispatchable;

    /**
     * @param  array<string, mixed>  $before
     * @param  array<string, mixed>  $after
     */
    public function __construct(
        public readonly string $type,
        public readonly string $name,
        public readonly array $before,
        public readonly array $after,
        public readonly int|string|null $actorId = null,
        public readonly ?string $note = null,
    ) {}

    /**
     * @return list<string>
     */
    public function changedKeys(): array
    {
        return array_values(array_unique([
            ...array_keys($this->before),
            ...array_keys($this->after),
        ]));
    }
}
