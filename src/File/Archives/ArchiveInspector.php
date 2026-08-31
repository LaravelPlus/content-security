<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Archives;

use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use PharData;
use PharException;
use PharFileInfo;
use RecursiveIteratorIterator;
use UnexpectedValueException;
use ZipArchive;

/**
 * Reads an archive's *table of contents*. Nothing is ever extracted to a
 * public path — every limit is decided from declared entry sizes, and a
 * nested archive is copied to a bounded temp file that is deleted straight
 * after. Guidance for hosts: never extract into the web root either.
 */
final class ArchiveInspector
{
    /** Nested archives above this size are counted, not opened. */
    private const MAX_NESTED_BYTES = 32 * 1024 * 1024;

    public function __construct(private readonly ArchiveLimits $limits) {}

    /**
     * @return array{threats: list<Threat>, metadata: array<string, mixed>}
     */
    public function inspect(FileReference $file): array
    {
        $format = $this->detectFormat($file);

        if ($format === null) {
            return ['threats' => [], 'metadata' => ['archive' => false]];
        }

        $state = new ArchiveScanState($this->limits);

        $threats = $format === 'zip'
            ? $this->inspectZip($file->path, $state, 1, $file->originalName)
            : $this->inspectPhar($file->path, $state, $file->originalName);

        return [
            'threats' => $threats,
            'metadata' => [
                'archive' => true,
                'format' => $format,
                'entries' => $state->files,
                'uncompressed_size' => $state->uncompressedSize,
                'compressed_size' => $state->compressedSize,
                'compression_ratio' => $state->ratio(),
                'max_depth_seen' => $state->deepest,
            ],
        ];
    }

    public function isArchive(FileReference $file): bool
    {
        return $this->detectFormat($file) !== null;
    }

    private function detectFormat(FileReference $file): ?string
    {
        $head = $file->head(512);

        if (str_starts_with($head, "PK\x03\x04") || str_starts_with($head, "PK\x05\x06")) {
            return 'zip';
        }

        if (str_starts_with($head, "\x1f\x8b")) {
            return 'gz';
        }

        // The tar magic lives at offset 257, not at the start of the file.
        if (strlen($head) > 262 && substr($head, 257, 5) === 'ustar') {
            return 'tar';
        }

        return null;
    }

    /**
     * @return list<Threat>
     */
    private function inspectZip(string $path, ArchiveScanState $state, int $depth, string $label): array
    {
        if (! class_exists(ZipArchive::class)) {
            return [Threat::make(
                name: 'archive.inspector_unavailable',
                level: ThreatLevel::Medium,
                source: 'archive',
                description: 'ext-zip is not installed, so this archive could not be inspected.',
            )];
        }

        $threats = [];
        $zip = new ZipArchive;

        if ($zip->open($path) !== true) {
            return [Threat::make(
                name: 'archive.unreadable',
                level: ThreatLevel::Medium,
                source: 'archive',
                description: sprintf('The archive [%s] could not be opened.', $label),
            )];
        }

        $state->seeDepth($depth);

        try {
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $entry = $zip->statIndex($i);

                if ($entry === false) {
                    continue;
                }

                $name = (string) $entry['name'];
                $uncompressed = (int) $entry['size'];
                $compressed = (int) $entry['comp_size'];
                $isDirectory = str_ends_with($name, '/');

                if (! $isDirectory) {
                    $state->addFile($uncompressed, $compressed);
                }

                foreach ($this->inspectEntryName($name, $label) as $threat) {
                    $threats[] = $threat;
                }

                foreach ($state->breaches() as $threat) {
                    $threats[] = $threat;
                }

                if ($state->exhausted()) {
                    // Past a hard limit the remaining entries can only
                    // confirm what we already know, at our expense.
                    break;
                }

                if ($isDirectory || ! $this->looksNested($name)) {
                    continue;
                }

                if ($depth >= $this->limits->maxDepth) {
                    $state->seeDepth($depth + 1);

                    foreach ($state->breaches() as $threat) {
                        $threats[] = $threat;
                    }

                    continue;
                }

                if ($uncompressed > 0 && $uncompressed <= self::MAX_NESTED_BYTES) {
                    foreach ($this->inspectNested($zip, $i, $name, $state, $depth) as $threat) {
                        $threats[] = $threat;
                    }
                }
            }
        } finally {
            $zip->close();
        }

        return $threats;
    }

    /**
     * @return list<Threat>
     */
    private function inspectNested(ZipArchive $zip, int $index, string $name, ArchiveScanState $state, int $depth): array
    {
        $stream = $zip->getStreamIndex($index);

        if (! is_resource($stream)) {
            return [];
        }

        $temp = tempnam(sys_get_temp_dir(), 'cs-arc-');

        if ($temp === false) {
            fclose($stream);

            return [];
        }

        $target = fopen($temp, 'wb');

        if (! is_resource($target)) {
            fclose($stream);
            @unlink($temp);

            return [];
        }

        try {
            // Bounded copy: a nested entry that lies about its size cannot
            // fill the disk from inside this loop.
            stream_copy_to_stream($stream, $target, self::MAX_NESTED_BYTES);
        } finally {
            fclose($target);
            fclose($stream);
        }

        try {
            return $this->inspectZip($temp, $state, $depth + 1, $name);
        } finally {
            @unlink($temp);
        }
    }

    /**
     * @return list<Threat>
     */
    private function inspectPhar(string $path, ArchiveScanState $state, string $label): array
    {
        $threats = [];
        $state->seeDepth(1);

        try {
            $archive = new PharData($path);

            /** @var PharFileInfo $entry */
            foreach (new RecursiveIteratorIterator($archive) as $entry) {
                $name = str_replace('phar://'.$path.'/', '', $entry->getPathname());
                $size = (int) $entry->getSize();
                $compressed = (int) $entry->getCompressedSize();
                $state->addFile($size, $compressed > 0 ? $compressed : $size);

                foreach ($this->inspectEntryName($name, $label) as $threat) {
                    $threats[] = $threat;
                }

                foreach ($state->breaches() as $threat) {
                    $threats[] = $threat;
                }

                if ($state->exhausted()) {
                    break;
                }
            }
        } catch (UnexpectedValueException|PharException $e) {
            $threats[] = Threat::make(
                name: 'archive.unreadable',
                level: ThreatLevel::Medium,
                source: 'archive',
                description: sprintf('The archive [%s] could not be read: %s', $label, $e->getMessage()),
            );
        }

        return $threats;
    }

    /**
     * @return list<Threat>
     */
    private function inspectEntryName(string $name, string $archive): array
    {
        $threats = [];

        // Zip Slip: an entry that escapes the extraction root. We never
        // extract, but a host that does would be writing outside its target.
        if (str_contains($name, '../')
            || str_contains($name, '..\\')
            || str_starts_with($name, '/')
            || preg_match('#^[a-zA-Z]:[\\\\/]#', $name) === 1
        ) {
            $threats[] = Threat::make(
                name: 'archive.path_traversal',
                level: ThreatLevel::Critical,
                source: 'archive',
                description: sprintf('Entry [%s] escapes the extraction directory.', $name),
                metadata: ['entry' => $name, 'archive' => $archive],
            );
        }

        if (str_contains($name, "\0")) {
            $threats[] = Threat::make(
                name: 'archive.null_byte_entry',
                level: ThreatLevel::Critical,
                source: 'archive',
                description: 'An entry name contains a null byte.',
                metadata: ['archive' => $archive],
            );
        }

        $extension = mb_strtolower(pathinfo($name, PATHINFO_EXTENSION));

        if ($extension !== '' && in_array($extension, $this->limits->forbiddenEntryExtensions, true)) {
            $threats[] = Threat::make(
                name: 'archive.executable_entry',
                level: ThreatLevel::High,
                source: 'archive',
                description: sprintf('Entry [%s] is an executable or script file.', $name),
                metadata: ['entry' => $name, 'extension' => $extension],
            );
        }

        return $threats;
    }

    private function looksNested(string $name): bool
    {
        return preg_match('/\.(zip|jar|apk|docx|xlsx|pptx|odt|ods)$/i', $name) === 1;
    }
}
