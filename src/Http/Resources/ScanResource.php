<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use LaravelPlus\ContentSecurity\Models\SecurityScan;

/**
 * The console's stable view of a scan. Eloquent models are never handed to
 * the frontend directly — a column rename would otherwise be a frontend
 * change, and a new column would leak by default.
 *
 * @mixin SecurityScan
 */
final class ScanResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        /** @var SecurityScan $scan */
        $scan = $this->resource;

        return [
            'id' => $scan->scan_id,
            'short_id' => mb_substr($scan->scan_id, -8),
            'type' => $scan->type->value,
            'status' => $scan->status->value,
            'scanner' => $scan->scanner,
            'policy' => $scan->policy,
            'subject' => $scan->original_filename ?? __('Text input'),
            'extension' => $scan->extension,
            'declared_mime' => $scan->declared_mime,
            'detected_mime' => $scan->detected_mime,
            'size' => $scan->file_size,
            'content_length' => $scan->content_length,
            'checksum' => $scan->checksum_sha256,
            'duration_ms' => $scan->duration_ms,
            'threat_count' => $scan->threat_count,
            'quarantined' => $scan->isQuarantined(),
            'created_at' => $scan->created_at?->toIso8601String(),
            'completed_at' => $scan->completed_at?->toIso8601String(),

            // Filesystem paths are operational detail and are withheld by
            // default. See config('content-security.admin.expose_paths').
            'quarantine_path' => $this->when(
                (bool) config('content-security.admin.expose_paths', false) && $scan->isQuarantined(),
                fn (): ?string => $scan->quarantine_path,
            ),

            'threats' => ThreatResource::collection($this->whenLoaded('threats')),
            'checks' => $this->when(
                $request->routeIs('*.scans.show'),
                fn (): array => $this->checks($scan),
            ),
        ];
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function checks(SecurityScan $scan): array
    {
        /** @var list<array<string, mixed>> $checks */
        $checks = (array) ($scan->metadata['checks'] ?? []);

        return array_values(array_map(static fn (array $check): array => [
            'check' => (string) ($check['check'] ?? ''),
            'status' => (string) ($check['status'] ?? 'clean'),
            'skipped' => (bool) ($check['skipped'] ?? false),
            'duration_ms' => (float) ($check['duration_ms'] ?? 0),
            'error' => $check['error'] ?? null,
            'metadata' => (array) ($check['metadata'] ?? []),
        ], $checks));
    }
}
