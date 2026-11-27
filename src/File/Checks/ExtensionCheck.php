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
    /** Suffixes that legitimately follow `.tar`. */
    private const array COMPRESSION_SUFFIXES = ['gz', 'bz2', 'xz', 'zst', 'lz', 'lzma', 'z'];

    /** Extensions a user would recognise, so a disguise would use them. */
    private const array KNOWN_EXTENSIONS = [
        'pdf', 'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pptm',
        'odt', 'ods', 'odp', 'rtf', 'txt', 'csv', 'md', 'xml', 'json', 'eml',
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg', 'bmp', 'tif', 'tiff', 'heic', 'ico',
        'mp3', 'mp4', 'm4a', 'mov', 'avi', 'mkv', 'wav', 'webm',
        'zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'iso', 'img', 'dmg',
        'htm', 'html', 'xhtml', 'shtml', 'swf',
    ];

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

        $disguises = $this->disguisedSegments($segments, $policy);

        if ($disguises !== []) {
            return Findings::of(Threat::make(
                name: 'file.multiple_extensions',
                level: ThreatLevel::Low,
                source: $this->key(),
                description: sprintf('The filename carries several extensions: .%s', implode('.', $segments)),
                metadata: ['segments' => $segments, 'disguised' => $disguises],
            ), [...$metadata, 'segments' => $segments]);
        }

        return Findings::none($metadata);
    }

    /**
     * Non-final segments that are themselves file extensions: the
     * `invoice.pdf.zip` / `photo.jpg.html` disguise. Versions, dates and
     * plain words (`CV.2026.final.pdf`, `Resume v2.1.pdf`) are not, and
     * neither is a compound archive suffix such as `.tar.gz`.
     *
     * @param  list<string>  $segments
     * @return list<string>
     */
    private function disguisedSegments(array $segments, FilePolicy $policy): array
    {
        $inner = array_slice($segments, 0, -1);

        if ($inner !== [] && end($inner) === 'tar' && in_array(end($segments), self::COMPRESSION_SUFFIXES, true)) {
            array_pop($inner);
        }

        // ponytail: a fixed list plus the policy allowlist; extend the list when a disguise slips past it.
        $known = [...self::KNOWN_EXTENSIONS, ...$policy->extensions];

        return array_values(array_unique(array_intersect($inner, $known)));
    }
}
