<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Controllers;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Inertia\Response as InertiaResponse;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanType;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use LaravelPlus\ContentSecurity\Http\Controllers\Concerns\RendersConsole;
use LaravelPlus\ContentSecurity\Http\Resources\ScanResource;
use LaravelPlus\ContentSecurity\Models\SecurityScan;

final class ScanController extends Controller
{
    use RendersConsole;

    public function index(Request $request): InertiaResponse|JsonResponse
    {
        $scans = SecurityScan::query()
            ->with('threats')
            ->tap(fn (Builder $query): Builder => $this->applyFilters($query, $request))
            ->latest('created_at')
            ->paginate($this->perPage($request))
            ->withQueryString();

        return $this->render($request, 'Scans/Index', [
            'scans' => ScanResource::collection($scans)->response()->getData(true),
            'filters' => $this->filters($request),
            'options' => [
                'statuses' => array_map(static fn (ScanStatus $s): string => $s->value, ScanStatus::cases()),
                'types' => array_map(static fn (ScanType $t): string => $t->value, ScanType::cases()),
                'levels' => array_map(static fn (ThreatLevel $l): string => $l->value, ThreatLevel::cases()),
                'scanners' => SecurityScan::query()
                    ->whereNotNull('scanner')
                    ->distinct()
                    ->orderBy('scanner')
                    ->pluck('scanner')
                    ->all(),
                'mimeTypes' => SecurityScan::query()
                    ->whereNotNull('detected_mime')
                    ->distinct()
                    ->orderBy('detected_mime')
                    ->limit(100)
                    ->pluck('detected_mime')
                    ->all(),
            ],
        ]);
    }

    public function show(Request $request, SecurityScan $scan): InertiaResponse|JsonResponse
    {
        $scan->load('threats');

        return $this->render($request, 'Scans/Show', [
            'scan' => (new ScanResource($scan))->response($request)->getData(true)['data'] ?? [],
            'timeline' => $this->timeline($scan),
        ]);
    }

    /**
     * @param  Builder<SecurityScan>  $query
     * @return Builder<SecurityScan>
     */
    private function applyFilters(Builder $query, Request $request): Builder
    {
        return $query
            ->when($request->filled('status'), fn (Builder $q): Builder => $q->where('status', $request->string('status')->value()))
            ->when($request->filled('type'), fn (Builder $q): Builder => $q->where('type', $request->string('type')->value()))
            ->when($request->filled('scanner'), fn (Builder $q): Builder => $q->where('scanner', $request->string('scanner')->value()))
            ->when($request->filled('mime'), fn (Builder $q): Builder => $q->where('detected_mime', $request->string('mime')->value()))
            ->when($request->filled('from'), fn (Builder $q): Builder => $q->where('created_at', '>=', $request->date('from')))
            ->when($request->filled('to'), fn (Builder $q): Builder => $q->where('created_at', '<=', $request->date('to')))
            ->when($request->filled('level'), fn (Builder $q): Builder => $q->whereHas(
                'threats',
                fn (Builder $threats): Builder => $threats->where('level', $request->string('level')->value()),
            ))
            ->when($request->filled('q'), function (Builder $q) use ($request): Builder {
                $term = $request->string('q')->value();

                // Bound the wildcard search to the columns that are indexed
                // or short. A LIKE across metadata JSON would table-scan.
                return $q->where(function (Builder $search) use ($term): void {
                    $search->where('original_filename', 'like', '%'.$term.'%')
                        ->orWhere('scan_id', $term)
                        ->orWhere('checksum_sha256', $term);
                });
            });
    }

    /**
     * @return array<string, string|null>
     */
    private function filters(Request $request): array
    {
        return [
            'status' => $request->string('status')->value() ?: null,
            'type' => $request->string('type')->value() ?: null,
            'scanner' => $request->string('scanner')->value() ?: null,
            'mime' => $request->string('mime')->value() ?: null,
            'level' => $request->string('level')->value() ?: null,
            'from' => $request->string('from')->value() ?: null,
            'to' => $request->string('to')->value() ?: null,
            'q' => $request->string('q')->value() ?: null,
        ];
    }

    /**
     * The life of one scan, as the detail page's timeline.
     *
     * @return list<array{label: string, at: string|null, state: string}>
     */
    private function timeline(SecurityScan $scan): array
    {
        $events = [
            ['label' => 'Received', 'at' => $scan->created_at?->toIso8601String(), 'state' => 'done'],
            ['label' => 'Scan started', 'at' => $scan->started_at?->toIso8601String(), 'state' => $scan->started_at === null ? 'pending' : 'done'],
        ];

        if ($scan->completed_at !== null) {
            $events[] = [
                'label' => match ($scan->status) {
                    ScanStatus::Clean => 'Passed every check',
                    ScanStatus::Suspicious => 'Flagged as suspicious',
                    ScanStatus::Infected => 'Threat detected',
                    ScanStatus::Failed => 'Scan failed',
                    ScanStatus::Quarantined => 'Threat detected',
                    default => 'Completed',
                },
                'at' => $scan->completed_at->toIso8601String(),
                'state' => $scan->status === ScanStatus::Clean ? 'done' : 'alert',
            ];
        }

        if ($scan->isQuarantined()) {
            $events[] = [
                'label' => 'Quarantined',
                'at' => $scan->updated_at?->toIso8601String(),
                'state' => 'alert',
            ];
        }

        return $events;
    }
}
