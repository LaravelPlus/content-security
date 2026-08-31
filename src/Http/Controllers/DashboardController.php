<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Controllers;

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

        return $rows;
    }
}
