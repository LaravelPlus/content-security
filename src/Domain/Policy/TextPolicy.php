<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Policy;

use Illuminate\Support\Str;
use LaravelPlus\ContentSecurity\Exceptions\PolicyNotFoundException;

/**
 * What a text field will accept. Far weaker than a file policy by nature —
 * see the security notes in the README: scanning text is a signal, escaping
 * output is the control.
 */
final readonly class TextPolicy implements SecurityPolicy
{
    /**
     * @param  array<string, bool>  $checks
     */
    public function __construct(
        private string $name,
        private string $label,
        public int $maxLength,
        private array $checks = [],
    ) {}

    /**
     * @param  array<string, mixed>  $config
     */
    public static function fromConfig(string $name, array $config): self
    {
        /** @var array<string, bool> $checks */
        $checks = array_map(
            static fn (mixed $on): bool => (bool) $on,
            (array) ($config['checks'] ?? []),
        );

        return new self(
            name: $name,
            label: (string) ($config['label'] ?? Str::headline($name)),
            maxLength: (int) ($config['max_length'] ?? 100_000),
            checks: $checks,
        );
    }

    public static function named(string $name): self
    {
        /** @var array<string, array<string, mixed>> $policies */
        $policies = (array) config('content-security.text.policies', []);

        if (! isset($policies[$name])) {
            throw PolicyNotFoundException::text($name, array_keys($policies));
        }

        return self::fromConfig($name, $policies[$name]);
    }

    public static function default(): self
    {
        return self::named((string) config('content-security.text.default_policy', 'default'));
    }

    public static function rich(): self
    {
        return self::named('rich');
    }

    public function name(): string
    {
        return $this->name;
    }

    public function label(): string
    {
        return $this->label;
    }

    public function wants(string $check): bool
    {
        return (bool) ($this->checks[$check] ?? true);
    }

    /**
     * @return array<string, bool>
     */
    public function checks(): array
    {
        return $this->checks;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'label' => $this->label,
            'type' => 'text',
            'max_length' => $this->maxLength,
            'checks' => $this->checks,
        ];
    }
}
