<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Checks;

use Illuminate\Support\Str;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * Allowlist over the filename's extension, plus the double-extension trick
 * (`invoice.pdf.php`, `avatar.php.jpg`) — a server misconfigured to match
 * `\.php` anywhere in the path will happily execute both.
 */
final class ExtensionCheck extends AbstractFileCheck
{
    public function key(): string
    {
        return 'extension';
    }

    public function label(): string
    {
        return 'Extension';
    }

    protected function inspect(FileReference $file, FilePolicy $policy, ScanContext $context): Findings
    {
        $extension = $file->extension();
        $metadata = ['extension' => $extension, 'allowed' => $policy->extensions];

        if ($extension === '') {
            return Findings::of(Threat::make(
                name: 'file.no_extension',
                level: ThreatLevel::Low,
                source: $this->key(),
                description: 'The filename carries no extension.',
            ), $metadata);
        }

        // Every segment of the name, not just the last one: a filename is
        // only as safe as its most dangerous part.
        $segments = array_map(
            static fn (string $part): string => Str::lower($part),
            array_slice(explode('.', $file->originalName), 1),
        );

        $forbidden = array_values(array_intersect($segments, $policy->forbiddenExtensions));

        if ($forbidden !== []) {
            return Findings::of(Threat::make(
                name: 'file.executable_extension',
                level: ThreatLevel::Critical,
                source: $this->key(),
                description: sprintf(
                    'The filename contains a server-executable extension: .%s',
                    implode(', .', $forbidden),
                ),
                metadata: ['segments' => $forbidden],
            ), [...$metadata, 'forbidden_segments' => $forbidden]);
        }

        if (! $policy->allowsExtension($extension)) {
            return Findings::of(Threat::make(
                name: 'file.extension_not_allowed',
                level: ThreatLevel::Medium,
                source: $this->key(),
                description: sprintf('Extension .%s is not on the policy allowlist.', $extension),
                metadata: ['extension' => $extension],
            ), $metadata);
        }

        if (count($segments) > 1) {
            return Findings::of(Threat::make(
                name: 'file.multiple_extensions',
                level: ThreatLevel::Low,
                source: $this->key(),
                description: sprintf('The filename carries several extensions: .%s', implode('.', $segments)),
                metadata: ['segments' => $segments],
            ), [...$metadata, 'segments' => $segments]);
        }

        return Findings::none($metadata);
    }
}
