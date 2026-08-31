<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Archives;

use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * Running totals for one archive tree, including everything nested inside
 * it. Totals are cumulative across depth on purpose: a bomb split over ten
 * inner archives is still a bomb.
 *
 * Each breach is reported once — a limit crossed on entry 12 of 40,000 must
 * not produce 39,988 identical threats.
 */
final class ArchiveScanState
{
    public int $files = 0;

    public int $uncompressedSize = 0;

    public int $compressedSize = 0;

    public int $deepest = 0;

    /** @var array<string, bool> */
    private array $reported = [];

    public function __construct(private readonly ArchiveLimits $limits) {}

    public function addFile(int $uncompressed, int $compressed): void
    {
        $this->files++;
        $this->uncompressedSize += max(0, $uncompressed);
        $this->compressedSize += max(0, $compressed);
    }

    public function seeDepth(int $depth): void
    {
        $this->deepest = max($this->deepest, $depth);
    }

    public function ratio(): float
    {
        return $this->compressedSize > 0
            ? round($this->uncompressedSize / $this->compressedSize, 2)
            : 0.0;
    }

    /**
     * @return list<Threat>
     */
    public function breaches(): array
    {
        $threats = [];

        if ($this->files > $this->limits->maxFiles && $this->once('files')) {
            $threats[] = Threat::make(
                name: 'archive.too_many_files',
                level: ThreatLevel::High,
                source: 'archive',
                description: sprintf('The archive holds more than %d files.', $this->limits->maxFiles),
                metadata: ['files' => $this->files, 'limit' => $this->limits->maxFiles],
            );
        }

        if ($this->uncompressedSize > $this->limits->maxUncompressedSize && $this->once('size')) {
            $threats[] = Threat::make(
                name: 'archive.uncompressed_size',
                level: ThreatLevel::High,
                source: 'archive',
                description: sprintf(
                    'The archive expands to more than %d bytes.',
                    $this->limits->maxUncompressedSize,
                ),
                metadata: ['uncompressed_size' => $this->uncompressedSize, 'limit' => $this->limits->maxUncompressedSize],
            );
        }

        // Only meaningful once there is enough compressed data for the ratio
        // to mean anything — a 20-byte header inflates to a wild ratio.
        if ($this->compressedSize > 1024
            && $this->ratio() > $this->limits->maxCompressionRatio
            && $this->once('ratio')
        ) {
            $threats[] = Threat::make(
                name: 'archive.compression_bomb',
                level: ThreatLevel::Critical,
                source: 'archive',
                description: sprintf(
                    'The archive compresses at %.1f:1, above the %d:1 limit — this is the shape of a zip bomb.',
                    $this->ratio(),
                    $this->limits->maxCompressionRatio,
                ),
                metadata: ['ratio' => $this->ratio(), 'limit' => $this->limits->maxCompressionRatio],
            );
        }

        if ($this->deepest > $this->limits->maxDepth && $this->once('depth')) {
            $threats[] = Threat::make(
                name: 'archive.max_depth',
                level: ThreatLevel::High,
                source: 'archive',
                description: sprintf('The archive nests deeper than %d levels.', $this->limits->maxDepth),
                metadata: ['depth' => $this->deepest, 'limit' => $this->limits->maxDepth],
            );
        }

        return $threats;
    }

    /** True once any hard limit is past — the caller should stop reading. */
    public function exhausted(): bool
    {
        return $this->files > $this->limits->maxFiles
            || $this->uncompressedSize > $this->limits->maxUncompressedSize;
    }

    private function once(string $key): bool
    {
        if (isset($this->reported[$key])) {
            return false;
        }

        return $this->reported[$key] = true;
    }
}
