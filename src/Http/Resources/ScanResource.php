<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Http\Resources\Json\JsonResource;
use LaravelPlus\ContentSecurity\Models\SecurityScan;
use Throwable;

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
    /**
     * @return array{kind: string, url: string|null}
     */
    private function preview(SecurityScan $scan): array
    {
        $mime = (string) ($scan->detected_mime ?? $scan->declared_mime ?? '');
        $kind = match (true) {
            str_starts_with($mime, 'image/') => 'image',
            $mime === 'application/pdf' => 'pdf',
            str_starts_with($mime, 'text/') => 'text',
            str_contains($mime, 'zip') || str_contains($mime, 'compressed') => 'archive',
            $scan->type->value === 'text' => 'text',
            default => 'file',
        };

        $metadata = (array) $scan->metadata;
        $disk = $metadata['disk'] ?? null;
        $path = $metadata['disk_path'] ?? null;

        if (! is_string($disk) || ! is_string($path)) {
            return ['kind' => $kind, 'url' => null];
        }

        try {
            $filesystem = Storage::disk($disk);

            if (! $filesystem->exists($path)) {
                return ['kind' => $kind, 'url' => null];
            }

            // Zaseben disk podpisano povezavo zna, javni pa ne rabi; kar od
            // tega ne uspe, pomeni predogled brez slike in ne napake zaslona.
            return ['kind' => $kind, 'url' => $filesystem->temporaryUrl($path, now()->addMinutes(15))];
        } catch (Throwable) {
            try {
                return ['kind' => $kind, 'url' => Storage::disk($disk)->url($path)];
            } catch (Throwable) {
                return ['kind' => $kind, 'url' => null];
            }
        }
    }

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
            // Kaj je bilo pregledano: slika se pokaze, vse drugo dobi ikono po
            // svojem tipu. Povezava nastane le za datoteko, ki se je na disku
            // in jo disk zna ponuditi -- nalozena datoteka je bila zacasna in
            // je po pregledu ni vec.
            'preview' => $this->preview($scan),
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
