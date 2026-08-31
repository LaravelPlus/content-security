<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Images;

use LaravelPlus\ContentSecurity\Contracts\ImageInspector as ImageInspectorContract;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * Proves an image is an image by decoding it, and optionally re-encodes it
 * so what reaches storage is pixels the server drew — not the uploader's
 * container, its metadata, or whatever it appended after the last marker.
 */
final class ImageInspector implements ImageInspectorContract
{
    private const DECODABLE = [
        IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF, IMAGETYPE_WEBP, IMAGETYPE_BMP,
    ];

    public function __construct(
        private readonly bool $stripMetadata = true,
        private readonly bool $reencode = false,
        private readonly int $maxPixels = 50_000_000,
    ) {}

    public static function fromConfig(): self
    {
        return new self(
            stripMetadata: (bool) config('content-security.images.strip_metadata', true),
            reencode: (bool) config('content-security.images.reencode', false),
            maxPixels: (int) config('content-security.images.max_pixels', 50_000_000),
        );
    }

    public function handles(FileReference $file): bool
    {
        return @getimagesize($file->path) !== false
            || $this->isVector($file);
    }

    /** SVG is XML, not pixels — it takes a different path entirely. */
    public function isVector(FileReference $file): bool
    {
        if ($file->extension() === 'svg') {
            return true;
        }

        return str_contains(mb_strtolower($file->head(1024)), '<svg');
    }

    public function inspect(FileReference $file): Findings
    {
        $info = @getimagesize($file->path);

        if ($info === false) {
            return Findings::of(Threat::make(
                name: 'image.undecodable',
                level: ThreatLevel::High,
                source: 'image',
                description: 'The file claims to be an image but no decoder recognises it.',
            ), ['decodable' => false]);
        }

        [$width, $height] = $info;
        $type = (int) $info[2];
        $pixels = $width * $height;

        $threats = [];
        $metadata = [
            'decodable' => true,
            'width' => $width,
            'height' => $height,
            'pixels' => $pixels,
            'image_type' => image_type_to_mime_type($type),
        ];

        // A "decompression bomb": tiny file, enormous canvas. Whatever
        // resizes it later allocates width * height * 4 bytes of RAM.
        if ($pixels > $this->maxPixels) {
            $threats[] = Threat::make(
                name: 'image.pixel_bomb',
                level: ThreatLevel::High,
                source: 'image',
                description: sprintf(
                    'The image is %d x %d (%d pixels), above the %d pixel limit.',
                    $width,
                    $height,
                    $pixels,
                    $this->maxPixels,
                ),
                metadata: ['pixels' => $pixels, 'limit' => $this->maxPixels],
            );
        }

        if (! in_array($type, self::DECODABLE, true)) {
            // AVIF and friends: getimagesize identified a header but GD on
            // this build may not decode it. Reported, not rejected.
            $metadata['full_decode'] = false;

            return Findings::of($threats, $metadata);
        }

        if (! function_exists('imagecreatefromstring')) {
            $metadata['full_decode'] = false;

            return Findings::of($threats, $metadata);
        }

        // Trailing data after the image's own end marker is the classic
        // polyglot: valid JPEG to a viewer, script to an interpreter.
        $trailing = $this->trailingBytes($file, $type);

        if ($trailing > 0) {
            $threats[] = Threat::make(
                name: 'image.trailing_data',
                level: ThreatLevel::Medium,
                source: 'image',
                description: sprintf('%d bytes follow the image data. Re-encoding removes them.', $trailing),
                metadata: ['trailing_bytes' => $trailing],
            );
        }

        $metadata['full_decode'] = true;
        $metadata['trailing_bytes'] = $trailing;

        return Findings::of($threats, $metadata);
    }

    /**
     * Rewrites the file as freshly encoded pixels. Destructive by design —
     * the caller decides whether it wants the original or the safe copy.
     *
     * @return bool true when the file was rewritten
     */
    public function reencode(FileReference $file): bool
    {
        if (! $this->reencode || ! function_exists('imagecreatefromstring')) {
            return false;
        }

        $info = @getimagesize($file->path);

        if ($info === false || ! in_array((int) $info[2], self::DECODABLE, true)) {
            return false;
        }

        if ($this->maxPixels < $info[0] * $info[1]) {
            return false;
        }

        $contents = @file_get_contents($file->path);

        if ($contents === false) {
            return false;
        }

        $image = @imagecreatefromstring($contents);
        unset($contents);

        if ($image === false) {
            return false;
        }

        try {
            $type = (int) $info[2];

            // GD never carries EXIF/XMP across, so re-encoding *is* the
            // metadata strip. The flag stays separate because a host may
            // want the strip without the quality loss of a JPEG round-trip.
            return match ($type) {
                IMAGETYPE_JPEG => imagejpeg($image, $file->path, 90),
                IMAGETYPE_PNG => imagepng($image, $file->path, 9),
                IMAGETYPE_GIF => imagegif($image, $file->path),
                IMAGETYPE_WEBP => function_exists('imagewebp') && imagewebp($image, $file->path, 90),
                default => false,
            };
        } finally {
            imagedestroy($image);
        }
    }

    public function stripsMetadata(): bool
    {
        return $this->stripMetadata;
    }

    public function reencodes(): bool
    {
        return $this->reencode;
    }

    /**
     * Bytes after the format's end-of-image marker.
     *
     * Streamed in overlapping chunks rather than read whole: this runs on
     * uploads sized by policy, and a check that allocates the file it is
     * inspecting is its own denial of service. Only JPEG, PNG and GIF have
     * a marker we can find cheaply; anything else reports zero rather than
     * guess.
     */
    private function trailingBytes(FileReference $file, int $type): int
    {
        $marker = match ($type) {
            IMAGETYPE_JPEG => "\xff\xd9",
            IMAGETYPE_PNG => "IEND\xae\x42\x60\x82",
            IMAGETYPE_GIF => "\x3b",
            default => null,
        };

        if ($marker === null) {
            return 0;
        }

        $markerLength = strlen($marker);
        $chunkSize = 65_536;
        $handle = $file->stream();

        $lastEnd = null;
        $offset = 0;
        $carry = '';

        try {
            while (($chunk = fread($handle, $chunkSize)) !== false && $chunk !== '') {
                // The overlap carries the previous tail forward so a marker
                // straddling a chunk boundary is still found.
                $window = $carry.$chunk;
                $windowStart = $offset - strlen($carry);
                $search = 0;

                while (($position = strpos($window, $marker, $search)) !== false) {
                    $lastEnd = $windowStart + $position + $markerLength;
                    $search = $position + 1;
                }

                $offset += strlen($chunk);
                // A one-byte marker (GIF) can never straddle a boundary, and
                // substr($s, -0) returns the whole string — which would grow
                // the carry without bound.
                $carry = $markerLength > 1 ? substr($window, -($markerLength - 1)) : '';
            }
        } finally {
            fclose($handle);
        }

        if ($lastEnd === null) {
            return 0;
        }

        return max(0, $file->size() - $lastEnd);
    }
}
