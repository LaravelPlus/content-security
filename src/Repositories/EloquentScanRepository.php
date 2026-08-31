<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Repositories;

use Illuminate\Support\Facades\DB;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanType;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Models\SecurityScan;
use LaravelPlus\ContentSecurity\Models\SecurityThreat;

/**
 * The audit trail, in the host's database.
 *
 * Privacy is enforced here rather than left to callers: text input is
 * reduced to a hash and a length, and a sample is stored only when the host
 * has explicitly opted in. Check metadata is filtered too — the HTML check
 * carries the sanitized document in its metadata, which is useful in memory
 * and is not something to write into an audit table.
 */
final class EloquentScanRepository implements ScanRepository
{
    /** Metadata keys that may hold user content and are never persisted. */
    private const REDACTED_KEYS = ['sanitized', 'content', 'text', 'body', 'sample', 'content_sample'];

    public function start(ScanContext $context, ?FileReference $file = null): void
    {
        SecurityScan::query()->updateOrCreate(
            ['scan_id' => (string) $context->scanId],
            [
                'type' => $context->type,
                'status' => ScanStatus::Pending,
                'policy' => $context->policy,
                'request_id' => $context->requestId,
                'user_id' => $context->userId === null ? null : (string) $context->userId,
                'original_filename' => $file?->originalName,
                'extension' => $file?->extension(),
                'declared_mime' => $file?->declaredMime,
                'file_size' => $file?->size(),
                'checksum_sha256' => $file?->checksum(),
                'started_at' => now(),
            ],
        );
    }

    public function markScanning(ScanId $id): void
    {
        $this->markStatus($id, ScanStatus::Scanning);
    }

    public function complete(ScanResult $result): void
    {
        DB::connection($this->connection())->transaction(function () use ($result): void {
            $scan = SecurityScan::query()->firstOrNew(['scan_id' => (string) $result->scanId()]);

            $metadata = $result->metadata();

            $scan->fill([
                'type' => $result->type(),
                'status' => $result->status(),
                'scanner' => $result->scanner(),
                'duration_ms' => (int) round($result->duration()),
                'threat_count' => count($result->threats()),
                'detected_mime' => $this->stringOrNull($metadata['detected_mime'] ?? null)
                    ?? $this->detectedMimeFromChecks($result),
                'checksum_sha256' => $this->stringOrNull($metadata['checksum_sha256'] ?? null) ?? $scan->checksum_sha256,
                'metadata' => $this->redact([
                    ...$metadata,
                    'checks' => array_map(
                        fn (array $check): array => [
                            ...$check,
                            'metadata' => $this->redact($check['metadata']),
                        ],
                        array_map(
                            static fn ($check): array => $check->toArray(),
                            $result->checks(),
                        ),
                    ),
                ]),
                'completed_at' => now(),
            ]);

            if ($scan->started_at === null) {
                $scan->started_at = now();
            }

            if ($result->type() === ScanType::Text || $result->type() === ScanType::Html) {
                $scan->content_length = isset($metadata['length']) ? (int) $metadata['length'] : null;
                $scan->original_filename = null;

                // Promoted to its own column so it is one field to clear,
                // one field to exclude from a report, and one field to point
                // at when someone asks what this table keeps.
                $sample = $metadata['content_sample'] ?? null;
                $scan->content_sample = is_string($sample) ? $sample : null;
            }

            $scan->save();

            // Rewritten rather than appended: a rescan of the same scan id
            // must not leave the previous run's threats behind.
            $scan->threats()->delete();

            foreach ($result->threats() as $threat) {
                $this->storeThreat($scan, $threat);
            }
        });
    }

    public function markStatus(ScanId $id, ScanStatus $status): void
    {
        SecurityScan::query()
            ->where('scan_id', (string) $id)
            ->update(['status' => $status->value, 'updated_at' => now()]);
    }

    /** @param array<string, mixed> $attributes */
    public function recordQuarantine(ScanId $id, array $attributes): void
    {
        SecurityScan::query()
            ->where('scan_id', (string) $id)
            ->update([
                ...$attributes,
                'status' => ScanStatus::Quarantined->value,
                'updated_at' => now(),
            ]);
    }

    public function find(ScanId $id): ?SecurityScan
    {
        return SecurityScan::query()
            ->with('threats')
            ->where('scan_id', (string) $id)
            ->first();
    }

    /**
     * @return array<string, int|float>
     */
    public function statistics(int $sinceHours = 24): array
    {
        $since = now()->subHours($sinceHours);

        /** @var array<string, int> $byStatus */
        $byStatus = SecurityScan::query()
            ->where('created_at', '>=', $since)
            ->selectRaw('status, count(*) as aggregate')
            ->groupBy('status')
            ->pluck('aggregate', 'status')
            ->map(static fn (mixed $count): int => (int) $count)
            ->all();

        $window = array_sum($byStatus);

        return [
            'total' => (int) SecurityScan::query()->count(),
            'window_hours' => $sinceHours,
            'window_total' => $window,
            'clean' => $byStatus[ScanStatus::Clean->value] ?? 0,
            'suspicious' => $byStatus[ScanStatus::Suspicious->value] ?? 0,
            'infected' => $byStatus[ScanStatus::Infected->value] ?? 0,
            'failed' => $byStatus[ScanStatus::Failed->value] ?? 0,
            'quarantined' => $byStatus[ScanStatus::Quarantined->value] ?? 0,
            'pending' => ($byStatus[ScanStatus::Pending->value] ?? 0) + ($byStatus[ScanStatus::Scanning->value] ?? 0),
            'avg_duration_ms' => round(
                (float) SecurityScan::query()->where('created_at', '>=', $since)->avg('duration_ms'),
                1,
            ),
            'threats' => (int) SecurityThreat::query()->where('created_at', '>=', $since)->count(),
        ];
    }

    public function prune(int $olderThanDays): int
    {
        // Threat rows cascade on the foreign key, so deleting scans is
        // enough — and is one statement rather than two passes.
        return (int) SecurityScan::query()
            ->where('created_at', '<', now()->subDays($olderThanDays))
            ->whereNull('quarantine_path')
            ->delete();
    }

    private function storeThreat(SecurityScan $scan, Threat $threat): void
    {
        $scan->threats()->create([
            'name' => mb_substr($threat->name, 0, 191),
            'source' => mb_substr($threat->source, 0, 64),
            'level' => $threat->level,
            'description' => $threat->description,
            'metadata' => $this->redact($threat->metadata),
            'created_at' => now(),
        ]);
    }

    private function detectedMimeFromChecks(ScanResult $result): ?string
    {
        foreach ($result->checks() as $check) {
            if ($check->check === 'mime') {
                return $this->stringOrNull($check->metadata['detected_mime'] ?? null);
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $metadata
     * @return array<string, mixed>
     */
    private function redact(array $metadata): array
    {
        foreach (self::REDACTED_KEYS as $key) {
            if (array_key_exists($key, $metadata)) {
                $value = $metadata[$key];
                $metadata[$key] = is_string($value)
                    ? sprintf('[redacted: %d characters]', mb_strlen($value))
                    : '[redacted]';
            }
        }

        return $metadata;
    }

    private function stringOrNull(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    private function connection(): ?string
    {
        /** @var string|null $connection */
        $connection = config('content-security.persistence.connection');

        return $connection;
    }
}
