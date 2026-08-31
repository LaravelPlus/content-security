<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Support;

use Illuminate\Support\Str;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;

/**
 * Server-side type detection. The browser's Content-Type header is a claim
 * by the uploader and is never used to decide anything here.
 */
final class MimeTypes
{
    /**
     * Extensions that legitimately carry more than one MIME type, or whose
     * detected type varies by libmagic build. Consulted only to decide
     * whether a mismatch is worth reporting.
     *
     * @var array<string, list<string>>
     */
    private const EXTENSION_MAP = [
        'jpg' => ['image/jpeg'],
        'jpeg' => ['image/jpeg'],
        'png' => ['image/png'],
        'gif' => ['image/gif'],
        'webp' => ['image/webp'],
        'avif' => ['image/avif'],
        'svg' => ['image/svg+xml', 'text/xml', 'text/plain', 'text/html'],
        'pdf' => ['application/pdf'],
        'txt' => ['text/plain'],
        'csv' => ['text/csv', 'text/plain', 'application/csv'],
        'rtf' => ['application/rtf', 'text/rtf'],
        'doc' => ['application/msword', 'application/vnd.ms-office', 'application/x-ole-storage'],
        'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
        'xls' => ['application/vnd.ms-excel', 'application/vnd.ms-office', 'application/x-ole-storage'],
        'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
        'ppt' => ['application/vnd.ms-powerpoint', 'application/vnd.ms-office', 'application/x-ole-storage'],
        'pptx' => ['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'],
        'odt' => ['application/vnd.oasis.opendocument.text', 'application/zip'],
        'ods' => ['application/vnd.oasis.opendocument.spreadsheet', 'application/zip'],
        'zip' => ['application/zip', 'application/x-zip-compressed'],
        'gz' => ['application/gzip', 'application/x-gzip'],
        'tar' => ['application/x-tar'],
        'tgz' => ['application/gzip', 'application/x-gzip'],
        'json' => ['application/json', 'text/plain'],
        'xml' => ['text/xml', 'application/xml', 'text/plain'],
        'mp4' => ['video/mp4'],
        'mp3' => ['audio/mpeg'],
    ];

    /**
     * Detected via libmagic — reads the file's own bytes.
     */
    public function detect(FileReference $file): ?string
    {
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $detected = @$finfo->file($file->path);

        return is_string($detected) && $detected !== '' ? Str::lower($detected) : null;
    }

    public function detectFromString(string $bytes): ?string
    {
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $detected = @$finfo->buffer($bytes);

        return is_string($detected) && $detected !== '' ? Str::lower($detected) : null;
    }

    /**
     * True when the detected type is a plausible reading of the extension.
     * Unknown extensions return true: an unmapped extension is the
     * extension check's business, not a MIME mismatch.
     */
    public function matchesExtension(string $extension, string $detectedMime): bool
    {
        $extension = Str::lower(ltrim($extension, '.'));
        $detectedMime = Str::lower($detectedMime);

        if (! isset(self::EXTENSION_MAP[$extension])) {
            return true;
        }

        return in_array($detectedMime, self::EXTENSION_MAP[$extension], true);
    }

    public function isKnownExtension(string $extension): bool
    {
        return isset(self::EXTENSION_MAP[Str::lower(ltrim($extension, '.'))]);
    }

    /**
     * @return list<string>
     */
    public function expectedFor(string $extension): array
    {
        return self::EXTENSION_MAP[Str::lower(ltrim($extension, '.'))] ?? [];
    }

    /**
     * The declared type is uploader-controlled. Comparing it with the
     * detected type is worth an audit note, never a decision.
     */
    public function declaredMatchesDetected(?string $declared, ?string $detected): bool
    {
        if ($declared === null || $detected === null) {
            return true;
        }

        return Str::lower($declared) === Str::lower($detected);
    }
}
