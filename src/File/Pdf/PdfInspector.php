<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Pdf;

use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * Reports what a PDF *can do*, not whether it is malicious.
 *
 * A PDF that parses is not a safe PDF — the format carries JavaScript,
 * embedded files, and actions that launch external programs, all of them
 * legal and all of them the delivery mechanism for most PDF attacks. So the
 * findings here are capabilities: an administrator decides what to make of
 * a document that wants to run script on open.
 *
 * Read as a bounded byte stream. Object streams can hide these markers
 * behind compression, which is a known limit of any non-rendering inspector
 * — the malware engine is the layer that sees inside them.
 */
final class PdfInspector
{
    private const CHUNK = 65_536;

    /**
     * @param  array<string, bool>  $flags
     */
    public function __construct(
        private readonly array $flags,
        private readonly int $maxObjects,
        private readonly int $scanBytes,
    ) {}

    public static function fromConfig(): self
    {
        return new self(
            flags: [
                'javascript' => (bool) config('content-security.pdf.block_javascript', true),
                'embedded_files' => (bool) config('content-security.pdf.block_embedded_files', true),
                'launch_actions' => (bool) config('content-security.pdf.block_launch_actions', true),
                'encrypted' => (bool) config('content-security.pdf.block_encrypted', true),
            ],
            maxObjects: (int) config('content-security.pdf.max_objects', 50_000),
            scanBytes: (int) config('content-security.pdf.scan_bytes', 20 * 1024 * 1024),
        );
    }

    public function isPdf(FileReference $file): bool
    {
        return str_starts_with($file->head(1024), '%PDF-');
    }

    /**
     * @return array{threats: list<Threat>, metadata: array<string, mixed>}
     */
    public function inspect(FileReference $file): array
    {
        $head = $file->head(1024);

        if (! str_starts_with($head, '%PDF-')) {
            return [
                'threats' => [Threat::make(
                    name: 'pdf.malformed',
                    level: ThreatLevel::Medium,
                    source: 'pdf',
                    description: 'The file does not begin with a PDF header.',
                )],
                'metadata' => ['valid_header' => false],
            ];
        }

        $markers = $this->countMarkers($file);
        $version = $this->version($head);
        $threats = [];

        $metadata = [
            'valid_header' => true,
            'version' => $version,
            'objects' => $markers['obj'],
            'truncated_scan' => $markers['truncated'],
            'has_javascript' => $markers['javascript'] > 0,
            'has_embedded_files' => $markers['embedded'] > 0,
            'has_launch_actions' => $markers['launch'] > 0,
            'has_open_action' => $markers['openaction'] > 0,
            'encrypted' => $markers['encrypt'] > 0,
        ];

        if ($markers['eof'] === 0) {
            $threats[] = Threat::make(
                name: 'pdf.no_eof_marker',
                level: ThreatLevel::Low,
                source: 'pdf',
                description: 'The PDF has no %%EOF marker; it is truncated or hand-assembled.',
            );
        }

        if ($this->flags['javascript'] && $markers['javascript'] > 0) {
            $threats[] = Threat::make(
                name: 'pdf.javascript',
                level: ThreatLevel::High,
                source: 'pdf',
                description: 'The PDF contains JavaScript.',
                metadata: ['occurrences' => $markers['javascript']],
            );
        }

        if ($markers['openaction'] > 0 && $markers['javascript'] > 0) {
            $threats[] = Threat::make(
                name: 'pdf.auto_execute',
                level: ThreatLevel::Critical,
                source: 'pdf',
                description: 'The PDF runs JavaScript on open (/OpenAction with /JS).',
            );
        }

        if ($this->flags['embedded_files'] && $markers['embedded'] > 0) {
            $threats[] = Threat::make(
                name: 'pdf.embedded_file',
                level: ThreatLevel::High,
                source: 'pdf',
                description: 'The PDF carries embedded files.',
                metadata: ['occurrences' => $markers['embedded']],
            );
        }

        if ($this->flags['launch_actions'] && $markers['launch'] > 0) {
            $threats[] = Threat::make(
                name: 'pdf.launch_action',
                level: ThreatLevel::Critical,
                source: 'pdf',
                description: 'The PDF contains a /Launch action, which starts an external program.',
                metadata: ['occurrences' => $markers['launch']],
            );
        }

        if ($this->flags['encrypted'] && $markers['encrypt'] > 0) {
            $threats[] = Threat::make(
                name: 'pdf.encrypted',
                level: ThreatLevel::Medium,
                source: 'pdf',
                description: 'The PDF is encrypted, so its contents cannot be inspected.',
            );
        }

        if ($markers['obj'] > $this->maxObjects) {
            $threats[] = Threat::make(
                name: 'pdf.excessive_objects',
                level: ThreatLevel::Medium,
                source: 'pdf',
                description: sprintf(
                    'The PDF declares %d objects, above the %d limit — a shape used to exhaust parsers.',
                    $markers['obj'],
                    $this->maxObjects,
                ),
                metadata: ['objects' => $markers['obj'], 'limit' => $this->maxObjects],
            );
        }

        return ['threats' => $threats, 'metadata' => $metadata];
    }

    /**
     * One streamed pass, counting every marker at once. Chunks overlap so a
     * marker split across a read boundary is still counted.
     *
     * @return array{obj: int, javascript: int, embedded: int, launch: int, openaction: int, encrypt: int, eof: int, truncated: bool}
     */
    private function countMarkers(FileReference $file): array
    {
        $patterns = [
            'obj' => '/\d+\s+\d+\s+obj\b/',
            'javascript' => '/\/(JavaScript|JS)\b/',
            'embedded' => '/\/(EmbeddedFile|EmbeddedFiles|Filespec)\b/',
            'launch' => '/\/Launch\b/',
            'openaction' => '/\/(OpenAction|AA)\b/',
            'encrypt' => '/\/Encrypt\b/',
            'eof' => '/%%EOF/',
        ];

        $counts = array_fill_keys(array_keys($patterns), 0);
        $overlap = 32;
        $handle = $file->stream();
        $read = 0;
        $carry = '';
        $truncated = false;

        try {
            while (($chunk = fread($handle, self::CHUNK)) !== false && $chunk !== '') {
                $read += strlen($chunk);
                $window = $carry.$chunk;

                foreach ($patterns as $key => $pattern) {
                    $counts[$key] += (int) preg_match_all($pattern, $window);
                }

                $carry = substr($window, -$overlap);

                if ($read >= $this->scanBytes) {
                    $truncated = true;
                    break;
                }
            }
        } finally {
            fclose($handle);
        }

        /** @var array{obj: int, javascript: int, embedded: int, launch: int, openaction: int, encrypt: int, eof: int} $counts */
        return [...$counts, 'truncated' => $truncated];
    }

    private function version(string $head): ?string
    {
        return preg_match('/^%PDF-(\d+\.\d+)/', $head, $matches) === 1 ? $matches[1] : null;
    }
}
