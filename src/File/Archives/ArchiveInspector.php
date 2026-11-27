<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Archives;

use LaravelPlus\ContentSecurity\Contracts\ArchiveInspector as ArchiveInspectorContract;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use Throwable;
use ZipArchive;

/**
 * Reads an archive's *table of contents*. Nothing is ever extracted to a
 * public path — every limit is decided from declared entry sizes, and a
 * nested archive is copied to a bounded temp file that is deleted straight
 * after. Guidance for hosts: never extract into the web root either.
 */
final class ArchiveInspector implements ArchiveInspectorContract
{
    /** Nested archives above this size are counted, not opened. */
    private const MAX_NESTED_BYTES = 32 * 1024 * 1024;

    public function __construct(private readonly ArchiveLimits $limits) {}

    public function inspect(FileReference $file): Findings
    {
        $format = $this->detectFormat($file);

        if ($format === null) {
            return Findings::none(['archive' => false]);
        }

        $state = new ArchiveScanState($this->limits);

        $threats = $format === 'zip'
            ? $this->inspectZip($file->path, $state, 1, $file->originalName)
            : $this->inspectTar($file, $format === 'gz', $state);

        return Findings::of($threats, [
            'archive' => true,
            'format' => $format,
            'entries' => $state->files,
            'uncompressed_size' => $state->uncompressedSize,
            'compressed_size' => $state->compressedSize,
            'compression_ratio' => $state->ratio(),
            'max_depth_seen' => $state->deepest,
        ]);
    }

    public function handles(FileReference $file): bool
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
     * Reads tar headers block by block, through zlib for .tar.gz (#5).
     *
     * PharData refused the extensionless upload temp path, and when it did
     * open a .tar.gz it inflated the whole stream before any limit applied.
     * Here every entry is counted from its header first and the loop stops
     * once a limit is past, so a gzip bomb is inflated at most up to
     * `max_uncompressed_size`. A stream that is not a valid tar is
     * unreadable, never clean.
     *
     * @return list<Threat>
     */
    private function inspectTar(FileReference $file, bool $gzipped, ArchiveScanState $state): array
    {
        $label = $file->originalName;
        $threats = [];
        $state->seeDepth(1);

        if ($gzipped) {
            // The ratio is whole-archive for a gzip stream: inflated entries over the file on disk.
            $state->compressedSize = $file->size();
        }

        $handle = @fopen(($gzipped ? 'compress.zlib://' : '').$file->path, 'rb');

        if (! is_resource($handle)) {
            return [$this->unreadable($label, 'it could not be opened')];
        }

        try {
            $longName = null;

            while (true) {
                $header = $this->readExactly($handle, 512);

                if ($header === null) {
                    return [...$threats, $this->unreadable($label, 'it ends before the end-of-archive marker')];
                }

                if ($header === str_repeat("\0", 512)) {
                    break;
                }

                if (! $this->validTarHeader($header)) {
                    return [...$threats, $this->unreadable($label, 'it is not a valid tar archive')];
                }

                $size = $this->tarSize($header);
                $type = $header[156];

                // GNU long names and PAX headers carry the next entry's real name as data.
                if ($type === 'L' || $type === 'x') {
                    $data = $size <= 65536 ? $this->readExactly($handle, $size) : null;

                    if ($data === null || ! $this->skip($handle, (512 - $size % 512) % 512)) {
                        return [...$threats, $this->unreadable($label, 'an extended header is malformed')];
                    }

                    $longName = $type === 'L' ? rtrim($data, "\0") : $this->paxPath($data) ?? $longName;

                    continue;
                }

                $name = $longName ?? $this->tarName($header);
                $longName = null;

                // Every entry with data counts, whatever its type: skipping it
                // still inflates it, so it must be bounded like a file.
                if ($type !== '5' || $size > 0) {
                    $state->addFile($size, $gzipped ? 0 : $size);
                }

                foreach ($this->inspectEntryName($name, $label) as $threat) {
                    $threats[] = $threat;
                }

                // A hard or symbolic link to an absolute or parent path writes
                // outside the target on extraction just like a ../ name does.
                if ($type === '1' || $type === '2') {
                    foreach ($this->inspectEntryName(rtrim(substr($header, 157, 100), "\0"), $label) as $threat) {
                        $threats[] = $threat;
                    }
                }

                foreach ($state->breaches() as $threat) {
                    $threats[] = $threat;
                }

                if ($state->exhausted()) {
                    // Stop before inflating the entry that crossed the limit.
                    break;
                }

                if (! $this->skip($handle, (int) (ceil($size / 512) * 512))) {
                    return [...$threats, $this->unreadable($label, 'an entry is truncated')];
                }
            }
        } catch (Throwable $e) {
            return [...$threats, $this->unreadable($label, $e->getMessage())];
        } finally {
            fclose($handle);
        }

        return $threats;
    }

    /** @param resource $handle */
    private function readExactly($handle, int $bytes): ?string
    {
        $data = '';

        while (strlen($data) < $bytes) {
            $chunk = fread($handle, max(1, min(65536, $bytes - strlen($data))));

            if ($chunk === false || $chunk === '') {
                return null;
            }

            $data .= $chunk;
        }

        return $data;
    }

    /**
     * Reads past entry data instead of seeking, so a gzip stream is inflated
     * only as far as entries already counted against the limits.
     *
     * @param  resource  $handle
     */
    private function skip($handle, int $bytes): bool
    {
        while ($bytes > 0) {
            $chunk = $this->readExactly($handle, min(65536, $bytes));

            if ($chunk === null) {
                return false;
            }

            $bytes -= strlen($chunk);
        }

        return true;
    }

    private function validTarHeader(string $header): bool
    {
        $stored = trim(substr($header, 148, 8), "\0 ");

        if ($stored === '' || preg_match('/^[0-7]+$/', $stored) !== 1) {
            return false;
        }

        // The checksum is the byte sum of the header with its own field read as spaces.
        return array_sum(unpack('C*', substr_replace($header, str_repeat(' ', 8), 148, 8)) ?: []) === octdec($stored);
    }

    private function tarSize(string $header): int
    {
        $field = substr($header, 124, 12);

        // GNU base-256 sizes (high bit set) mean an entry of 8 GiB or more.
        if ((ord($field[0]) & 0x80) !== 0) {
            return PHP_INT_MAX;
        }

        return (int) octdec(trim($field, "\0 ") ?: '0');
    }

    private function tarName(string $header): string
    {
        $name = rtrim(substr($header, 0, 100), "\0");
        $prefix = substr($header, 257, 5) === 'ustar' ? rtrim(substr($header, 345, 155), "\0") : '';

        return $prefix === '' ? $name : $prefix.'/'.$name;
    }

    private function paxPath(string $data): ?string
    {
        // Records are "<length> <key>=<value>\n".
        return preg_match('/(?:^|\n)\d+ path=([^\n]*)\n/', $data, $match) === 1 ? $match[1] : null;
    }

    private function unreadable(string $label, string $reason): Threat
    {
        return Threat::make(
            name: 'archive.unreadable',
            level: ThreatLevel::Medium,
            source: 'archive',
            description: sprintf('The archive [%s] could not be read: %s.', $label, $reason),
        );
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
