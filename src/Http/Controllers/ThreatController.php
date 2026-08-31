<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Inertia\Response as InertiaResponse;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use LaravelPlus\ContentSecurity\Http\Controllers\Concerns\RendersConsole;
use LaravelPlus\ContentSecurity\Models\SecurityThreat;

/**
 * Threats aggregated by signature rather than listed one by one: forty
 * occurrences of the same finding is one thing to look at, not forty.
 */
final class ThreatController extends Controller
{
    use RendersConsole;

    public function __invoke(Request $request): InertiaResponse|JsonResponse
    {
        $threats = SecurityThreat::query()
            ->selectRaw('name, level, source')
            ->selectRaw('count(*) as occurrences')
            ->selectRaw('min(created_at) as first_seen')
            ->selectRaw('max(created_at) as last_seen')
            ->when($request->filled('level'), fn ($query) => $query->where('level', $request->string('level')->value()))
            ->when($request->filled('q'), fn ($query) => $query->where('name', 'like', '%'.$request->string('q')->value().'%'))
            ->when($request->filled('from'), fn ($query) => $query->where('created_at', '>=', $request->date('from')))
            ->groupBy('name', 'level', 'source')
            ->orderByDesc('occurrences')
            ->paginate($this->perPage($request))
            ->withQueryString()
            ->through(static fn (SecurityThreat $threat): array => [
                'name' => $threat->name,
                'level' => $threat->level->value,
                'source' => $threat->source,
                'occurrences' => (int) $threat->getAttribute('occurrences'),
                'first_seen' => (string) $threat->getAttribute('first_seen'),
                'last_seen' => (string) $threat->getAttribute('last_seen'),
            ]);

        return $this->render($request, 'Threats/Index', [
            'threats' => $threats->toArray(),
            'filters' => [
                'level' => $request->string('level')->value() ?: null,
                'q' => $request->string('q')->value() ?: null,
                'from' => $request->string('from')->value() ?: null,
            ],
            'options' => [
                'levels' => array_map(static fn (ThreatLevel $l): string => $l->value, ThreatLevel::cases()),
            ],
        ]);
    }
}
