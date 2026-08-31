<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Checks;

use Illuminate\Support\Str;
use LaravelPlus\ContentSecurity\Contracts\FileCheck;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * Allowlist over the filename's extension, plus the classic double-extension
 * trick (`invoice.pdf.php`, `avatar.php.jpg`) — a server misconfigured to
 * match `\.php` anywhere in the path executes both.
 */
final class ExtensionCheck implements FileCheck
{
    public function key(): string
    {
        return 'extension';
    }

    public function label(): string
    {
        return 'Extension';
    }

    public function appliesTo(FileReference $file, FilePolicy $policy): bool
    {
        return true;
    }

    public function check(FileReference $file, FilePolicy $policy, ScanContext $context): CheckResult
    {
        $extension = $file->extension();
        $metadata = ['extension' => $extension, 'allowed' => $policy->extensions];

        if ($extension === '') {
            return CheckResult::suspicious($this->key(), Threat::make(
                name: 'file.no_extension',
                level: ThreatLevel::Low,
                source: $this->key(),
                description: 'The filename carries no extension.',
            ), $metadata);
        }

        // Every segment of the name, not just the last: a name is only as
        // safe as its most dangerous part.
        $segments = array_map(
            static fn (string $part): string => Str::lower($part),
            array_slice(explode('.', $file->originalName), 1),
        );

        $forbidden = array_values(array_intersect($segments, $policy->forbiddenExtensions));

        if ($forbidden !== []) {
            return CheckResult::infected($this->key(), Threat::make(
                name: 'file.executable_extension',
                level: ThreatLevel::Critical,
                source: $this->key(),
                description: sprintf('The filename contains a server-executable extension: .%s', implode(', .', $forbidden)),
                metadata: ['segments' => $forbidden],
            ), [...$metadata, 'forbidden_segments' => $forbidden]);
        }

        if (! $policy->allowsExtension($extension)) {
            return CheckResult::infected($this->key(), Threat::make(
                name: 'file.extension_not_allowed',
                level: ThreatLevel::High,
                source: $this->key(),
                description: sprintf('Extension .%s is not on the policy allowlist.', $extension),
                metadata: ['extension' => $extension],
            ), $metadata);
        }

        if (count($segments) > 1) {
            return CheckResult::suspicious($this->key(), Threat::make(
                name: 'file.multiple_extensions',
                level: ThreatLevel::Low,
                source: $this->key(),
                description: sprintf('The filename carries several extensions: .%s', implode('.', $segments)),
                metadata: ['segments' => $segments],
            ), [...$metadata, 'segments' => $segments]);
        }

        return CheckResult::passed($this->key(), $metadata);
    }
}
