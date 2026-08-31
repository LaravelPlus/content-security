<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Policy;

use Illuminate\Support\Str;
use LaravelPlus\ContentSecurity\Exceptions\PolicyNotFoundException;

/**
 * What a given upload slot will accept. Allowlist-shaped: an extension or
 * MIME type not named here is refused, which is the only way to stay ahead
 * of formats nobody has thought of yet.
 */
final readonly class FilePolicy implements SecurityPolicy
{
    /**
     * @param  list<string>  $extensions
     * @param  list<string>  $mimeTypes  empty = derive from the extensions
     * @param  array<string, bool>  $checks
     * @param  list<string>  $forbiddenExtensions
     */
    public function __construct(
        private string $name,
        private string $label,
        public int $maxSize,
        public array $extensions,
        public array $mimeTypes = [],
        private array $checks = [],
        public FailureAction $onThreat = FailureAction::Quarantine,
        public array $forbiddenExtensions = [],
    ) {}

    /**
     * @param  array<string, mixed>  $config
     * @param  list<string>  $forbiddenExtensions
     */
    public static function fromConfig(string $name, array $config, array $forbiddenExtensions = []): self
    {
        /** @var list<string> $extensions */
        $extensions = array_values(array_map(
            static fn (string $ext): string => Str::lower(ltrim($ext, '.')),
            (array) ($config['extensions'] ?? []),
        ));

        /** @var list<string> $mimeTypes */
        $mimeTypes = array_values(array_map(
            static fn (string $mime): string => Str::lower($mime),
            (array) ($config['mime_types'] ?? []),
        ));

        /** @var array<string, bool> $checks */
        $checks = array_map(
            static fn (mixed $on): bool => (bool) $on,
            (array) ($config['checks'] ?? []),
        );

        return new self(
            name: $name,
            label: (string) ($config['label'] ?? Str::headline($name)),
            maxSize: (int) ($config['max_size'] ?? 10 * 1024 * 1024),
            extensions: $extensions,
            mimeTypes: $mimeTypes,
            checks: $checks,
            onThreat: FailureAction::tryFrom((string) ($config['on_threat'] ?? 'quarantine')) ?? FailureAction::Quarantine,
            forbiddenExtensions: array_values(array_map(
                static fn (string $ext): string => Str::lower(ltrim($ext, '.')),
                $forbiddenExtensions,
            )),
        );
    }

    /** Named policy from config. */
    public static function named(string $name): self
    {
        /** @var array<string, array<string, mixed>> $policies */
        $policies = (array) config('content-security.files.policies', []);

        if (! isset($policies[$name])) {
            throw PolicyNotFoundException::file($name, array_keys($policies));
        }

        /** @var list<string> $forbidden */
        $forbidden = (array) config('content-security.files.forbidden_extensions', []);

        return self::fromConfig($name, $policies[$name], $forbidden);
    }

    public static function default(): self
    {
        return self::named((string) config('content-security.files.default_policy', 'default'));
    }

    public static function images(): self
    {
        return self::named('images');
    }

    public static function documents(): self
    {
        return self::named('documents');
    }

    /**
     * Build one inline, for a slot that does not deserve a config entry.
     *
     * @param  list<string>  $extensions
     * @param  array<string, mixed>  $overrides
     */
    public static function custom(array $extensions, int $maxSize, array $overrides = []): self
    {
        /** @var list<string> $forbidden */
        $forbidden = (array) config('content-security.files.forbidden_extensions', []);

        return self::fromConfig('custom', [
            'label' => 'Custom Policy',
            'extensions' => $extensions,
            'max_size' => $maxSize,
            ...$overrides,
        ], $forbidden);
    }

    public function name(): string
    {
        return $this->name;
    }

    public function label(): string
    {
        return $this->label;
    }

    /** Unlisted checks default to on — a new check ships enabled, not silent. */
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

    public function allowsExtension(string $extension): bool
    {
        $extension = Str::lower(ltrim($extension, '.'));

        if ($extension === '' || in_array($extension, $this->forbiddenExtensions, true)) {
            return false;
        }

        return in_array($extension, $this->extensions, true);
    }

    public function isForbiddenExtension(string $extension): bool
    {
        return in_array(Str::lower(ltrim($extension, '.')), $this->forbiddenExtensions, true);
    }

    /**
     * With no explicit MIME allowlist the extension list is the control, and
     * the MIME check limits itself to catching mismatches.
     */
    public function allowsMime(string $mime): bool
    {
        if ($this->mimeTypes === []) {
            return true;
        }

        return in_array(Str::lower($mime), $this->mimeTypes, true);
    }

    public function hasMimeAllowlist(): bool
    {
        return $this->mimeTypes !== [];
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'label' => $this->label,
            'type' => 'file',
            'max_size' => $this->maxSize,
            'extensions' => $this->extensions,
            'mime_types' => $this->mimeTypes,
            'checks' => $this->checks,
            'on_threat' => $this->onThreat->value,
            'forbidden_extensions' => $this->forbiddenExtensions,
        ];
    }
}
