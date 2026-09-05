<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Controllers;

use Carbon\CarbonImmutable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Inertia\Response as InertiaResponse;
use LaravelPlus\ContentSecurity\ContentSecurity;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Http\Controllers\Concerns\RendersConsole;
use LaravelPlus\ContentSecurity\Http\Resources\ScannerHealthResource;
use LaravelPlus\ContentSecurity\Http\Resources\ScanResource;
use LaravelPlus\ContentSecurity\Models\SecurityScan;
use LaravelPlus\ContentSecurity\Models\SecurityThreat;
use LaravelPlus\ContentSecurity\Support\ScannerHealth;

final class DashboardController extends Controller
{
    use RendersConsole;

    public function __invoke(
        Request $request,
        ScanRepository $repository,
        ContentSecurity $security,
    ): InertiaResponse|JsonResponse {
        $hours = max(1, min(720, $request->integer('hours', 24)));
        $statistics = $repository->statistics($hours);
        $health = $security->health();

        return $this->render($request, 'Dashboard', [
            'statistics' => $statistics,
            // Kaj caka cloveka, ni vprasanje izbranega okna: datoteka v
            // karanteni caka tudi, ce je prisla pred tednom dni. Okno velja za
            // promet, stanje pa se steje celo.
            'waiting' => [
                'threats' => SecurityThreat::query()->count(),
                'quarantined' => SecurityScan::query()->whereNotNull('quarantine_path')->count(),
                'failed' => SecurityScan::query()->where('status', ScanStatus::Failed)->count(),
            ],
            'hours' => $hours,
            'health' => ScannerHealthResource::collection($health)->resolve(),
            'posture' => $this->posture($statistics, $health),
            'recentScans' => ScanResource::collection(
                SecurityScan::query()
                    ->with('threats')
                    ->latest('created_at')
                    ->limit(10)
                    ->get(),
            )->resolve(),
            'recentThreats' => SecurityThreat::query()
                ->latest('created_at')
                ->limit(8)
                ->get()
                ->map(static fn (SecurityThreat $threat): array => [
                    'name' => $threat->name,
                    'level' => $threat->level->value,
                    'source' => $threat->source,
                    'created_at' => $threat->created_at?->toIso8601String(),
                ])
                ->all(),
            'timeline' => $this->timeline($hours),
            // Kako se pregledi koncajo, kaj se nalaga in kako dolgo traja --
            // troje, ki ga stevilke same ne povedo: delez, sestava in rep.
            'outcomes' => $this->outcomes($statistics),
            'fileTypes' => $this->fileTypes($hours),
            'durations' => $this->durations($hours),
        ]);
    }

    /**
     * The single headline the page leads with.
     *
     * Note that scan *failures* count against health as much as detections
     * do. A fail-closed application whose engine is down is rejecting every
     * upload, and "no threats detected" would be a dangerously reassuring
     * way to describe that.
     *
     * @param  array<string, int|float>  $statistics
     * @param  list<ScannerHealth>  $health
     * @return array{state: string, headline: string, detail: string}
     */
    private function posture(array $statistics, array $health): array
    {
        foreach ($health as $scanner) {
            // Only the active engine matters. Every configured driver is
            // listed, and an idle one is not an outage.
            if (! $scanner->active) {
                continue;
            }

            if (! $scanner->enabled) {
                // The active driver is `null`: nothing is scanned for
                // malware at all. Previously invisible here, because a
                // disabled driver was skipped along with the idle ones.
                return [
                    'state' => 'warning',
                    'headline' => 'No malware engine',
                    'detail' => 'Files are checked structurally, but nothing is scanned for known malware.',
                ];
            }

            if (! $scanner->online) {
                return [
                    'state' => 'critical',
                    'headline' => 'Scanner offline',
                    'detail' => sprintf('%s is not responding. Uploads are being rejected.', $scanner->scanner),
                ];
            }
        }

        if (($statistics['infected'] ?? 0) > 0) {
            return [
                'state' => 'critical',
                'headline' => 'Malware detected',
                'detail' => sprintf('%d infected upload(s) in this period.', (int) $statistics['infected']),
            ];
        }

        if (($statistics['failed'] ?? 0) > 0) {
            return [
                'state' => 'warning',
                'headline' => 'Scans failing',
                'detail' => sprintf('%d scan(s) could not complete.', (int) $statistics['failed']),
            ];
        }

        if (($statistics['suspicious'] ?? 0) > 0) {
            return [
                'state' => 'warning',
                'headline' => 'Suspicious content flagged',
                'detail' => sprintf('%d item(s) need review.', (int) $statistics['suspicious']),
            ];
        }

        return [
            'state' => 'healthy',
            'headline' => 'System healthy',
            'detail' => 'No threats detected and every scanner is responding.',
        ];
    }

    /**
     * Izidi pregledov kot deli celote. Stanja so rezervirane barve in gredo
     * vedno z oznako -- barva sama ni podatek za tistega, ki je ne loci.
     *
     * @param  array<string, int|float>  $statistics
     * @return list<array{key: string, label: string, value: int}>
     */
    private function outcomes(array $statistics): array
    {
        $rows = [
            ['key' => 'clean', 'label' => 'Clean', 'value' => (int) ($statistics['clean'] ?? 0)],
            ['key' => 'suspicious', 'label' => 'Suspicious', 'value' => (int) ($statistics['suspicious'] ?? 0)],
            ['key' => 'infected', 'label' => 'Malware', 'value' => (int) ($statistics['infected'] ?? 0)],
            ['key' => 'failed', 'label' => 'Failed', 'value' => (int) ($statistics['failed'] ?? 0)],
        ];

        return array_values(array_filter($rows, static fn (array $row): bool => $row['value'] > 0));
    }

    /**
     * Kaj se dejansko nalaga. Rep se zdruzi v "Other": deveta rezina je barva,
     * ki je nihce ne prebere.
     *
     * @return list<array{label: string, value: int}>
     */
    private function fileTypes(int $hours): array
    {
        $rows = SecurityScan::query()
            ->where('type', 'file')
            ->where('created_at', '>=', now()->subHours($hours))
            ->selectRaw('coalesce(detected_mime, declared_mime) as mime, count(*) as total')
            ->groupBy('mime')
            ->orderByDesc('total')
            ->get();

        $top = $rows->take(5)->map(static fn ($row): array => [
            'label' => (string) ($row->getAttribute('mime') ?: 'unknown'),
            'value' => (int) $row->getAttribute('total'),
        ])->values()->all();

        $rest = (int) $rows->skip(5)->sum(static fn ($row): int => (int) $row->getAttribute('total'));

        if ($rest > 0) {
            $top[] = ['label' => 'Other', 'value' => $rest];
        }

        return $top;
    }

    /**
     * Kako dolgo traja pregled. Povprecje samo skriva rep, zato gresta z njim
     * se mediana in 95. percentil -- tisto, kar cuti clovek, ki caka.
     *
     * @return array{median: int, p95: int, slowest: int, count: int}
     */
    private function durations(int $hours): array
    {
        $values = SecurityScan::query()
            ->where('created_at', '>=', now()->subHours($hours))
            ->where('duration_ms', '>', 0)
            ->orderBy('duration_ms')
            ->pluck('duration_ms')
            ->map(static fn ($value): int => (int) $value)
            ->values();

        if ($values->isEmpty()) {
            return ['median' => 0, 'p95' => 0, 'slowest' => 0, 'count' => 0];
        }

        $at = static fn (float $quantile): int => (int) $values[
            min($values->count() - 1, (int) floor($quantile * ($values->count() - 1)))
        ];

        return [
            'median' => $at(0.5),
            'p95' => $at(0.95),
            'slowest' => (int) $values->last(),
            'count' => $values->count(),
        ];
    }

    /**
     * Scans per hour (or per day over a long window), for the sparkline.
     *
     * @return list<array{bucket: string, total: int, threats: int}>
     */
    private function timeline(int $hours): array
    {
        $daily = $hours > 48;
        $format = $daily ? '%Y-%m-%d' : '%Y-%m-%d %H:00';

        $driver = DB::connection(config('content-security.persistence.connection'))->getDriverName();

        // date_format() on MySQL, strftime() on SQLite. Both ship with
        // Laravel's supported drivers; anything else falls back to PHP-side
        // grouping rather than guessing at SQL dialect.
        $expression = match ($driver) {
            'mysql', 'mariadb' => sprintf("date_format(created_at, '%s')", $daily ? '%Y-%m-%d' : '%Y-%m-%d %H:00'),
            'sqlite' => sprintf("strftime('%s', created_at)", $daily ? '%Y-%m-%d' : '%Y-%m-%d %H:00'),
            'pgsql' => sprintf("to_char(created_at, '%s')", $daily ? 'YYYY-MM-DD' : 'YYYY-MM-DD HH24:00'),
            default => null,
        };

        if ($expression === null) {
            return [];
        }

        /** @var list<array{bucket: string, total: int, threats: int}> $rows */
        $rows = SecurityScan::query()
            ->where('created_at', '>=', now()->subHours($hours))
            ->selectRaw($expression.' as bucket')
            ->selectRaw('count(*) as total')
            ->selectRaw('sum(case when status in (?, ?, ?) then 1 else 0 end) as threats', [
                ScanStatus::Infected->value,
                ScanStatus::Suspicious->value,
                ScanStatus::Quarantined->value,
            ])
            ->groupBy('bucket')
            ->orderBy('bucket')
            ->get()
            ->map(static fn (SecurityScan $row): array => [
                'bucket' => (string) $row->getAttribute('bucket'),
                'total' => (int) $row->getAttribute('total'),
                'threats' => (int) $row->getAttribute('threats'),
            ])
            ->all();

        unset($format);

        return $this->fillBuckets($rows, $hours, $daily);
    }

    /**
     * Dopolni prazna vedra.
     *
     * Poizvedba vrne le tiste ure oziroma dneve, ko se je kaj zgodilo, in graf
     * je zato pokazal tri stolpce na levi in dve tretjini prazne sirine --
     * kot da o preostanku ne vemo nicesar. Dan brez pregleda je izmerjena
     * nicla in tako mora tudi izgledati.
     *
     * @param  list<array{bucket: string, total: int, threats: int}>  $rows
     * @return list<array{bucket: string, total: int, threats: int}>
     */
    private function fillBuckets(array $rows, int $hours, bool $daily): array
    {
        $known = [];

        foreach ($rows as $row) {
            $known[$row['bucket']] = $row;
        }

        $cursor = $daily
            ? CarbonImmutable::now()->subHours($hours)->startOfDay()
            : CarbonImmutable::now()->subHours($hours)->startOfHour();
        $end = CarbonImmutable::now();
        $format = $daily ? 'Y-m-d' : 'Y-m-d H:00';
        $filled = [];

        while ($cursor <= $end) {
            $bucket = $cursor->format($format);
            $filled[] = $known[$bucket] ?? ['bucket' => $bucket, 'total' => 0, 'threats' => 0];
            $cursor = $daily ? $cursor->addDay() : $cursor->addHour();
        }

        return $filled;
    }
}
