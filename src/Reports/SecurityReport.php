<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Reports;

use Carbon\CarbonImmutable;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Models\SecurityScan;
use LaravelPlus\ContentSecurity\Models\SecurityThreat;
use LaravelPlus\ContentSecurity\Support\ScannerHealth;

/**
 * The figures behind a daily or weekly digest.
 *
 * Read-only and self-contained so the same object serves the mail, the
 * console command and (should anyone want it) an API endpoint.
 */
final readonly class SecurityReport
{
    /**
     * @param  array<string, int>  $counts
     * @param  list<array{name: string, level: string, occurrences: int}>  $topThreats
     * @param  list<ScannerHealth>  $scanners
     * @param  list<array{at: CarbonImmutable, status: string, subject: string, policy: ?string, user: ?string, threats: list<string>, error: ?string}>  $incidents  Worst first, capped at 10.
     * @param  int  $incidentsTotal  Every non-clean scan in the window, so the mail can say "and N more".
     */
    public function __construct(
        public string $period,
        public CarbonImmutable $from,
        public CarbonImmutable $to,
        public array $counts,
        public float $averageDurationMs,
        public array $topThreats,
        public array $scanners,
        public array $incidents = [],
        public int $incidentsTotal = 0,
    ) {}

    /**
     * @param  list<ScannerHealth>  $scanners
     */
    public static function build(
        string $period,
        CarbonImmutable $from,
        CarbonImmutable $to,
        array $scanners = [],
    ): self {
        /** @var array<string, int> $byStatus */
        $byStatus = SecurityScan::query()
            ->whereBetween('created_at', [$from, $to])
            ->selectRaw('status, count(*) as aggregate')
            ->groupBy('status')
            ->pluck('aggregate', 'status')
            ->map(static fn (mixed $count): int => (int) $count)
            ->all();

        $counts = [
            'total' => array_sum($byStatus),
            'clean' => $byStatus[ScanStatus::Clean->value] ?? 0,
            'suspicious' => $byStatus[ScanStatus::Suspicious->value] ?? 0,
            'infected' => $byStatus[ScanStatus::Infected->value] ?? 0,
            'failed' => $byStatus[ScanStatus::Failed->value] ?? 0,
            'quarantined' => $byStatus[ScanStatus::Quarantined->value] ?? 0,
        ];

        /** @var list<array{name: string, level: string, occurrences: int}> $topThreats */
        $topThreats = SecurityThreat::query()
            ->whereBetween('created_at', [$from, $to])
            ->selectRaw('name, level, count(*) as occurrences')
            ->groupBy('name', 'level')
            ->orderByDesc('occurrences')
            ->limit(10)
            ->get()
            ->map(static fn (SecurityThreat $threat): array => [
                'name' => $threat->name,
                'level' => $threat->level->value,
                'occurrences' => (int) $threat->getAttribute('occurrences'),
            ])
            ->all();

        $bad = SecurityScan::query()
            ->whereBetween('created_at', [$from, $to])
            ->whereIn('status', array_map(static fn (ScanStatus $s): string => $s->value, [
                ScanStatus::Quarantined, ScanStatus::Infected, ScanStatus::Failed, ScanStatus::Suspicious,
            ]));

        $incidentsTotal = (clone $bad)->count();

        // Worst first (the enum's own severity), newest first within a status.
        $incidents = $bad->with('threats')
            ->latest('created_at')
            ->limit(200)
            ->get()
            ->sortByDesc(static fn (SecurityScan $scan): int => $scan->status->severity())
            ->take(10)
            ->map(static fn (SecurityScan $scan): array => [
                'at' => CarbonImmutable::instance($scan->created_at),
                'status' => $scan->status->value,
                'subject' => $scan->original_filename ?? $scan->type->value,
                'policy' => $scan->policy,
                'user' => $scan->user_id,
                'threats' => $scan->threats->pluck('name')->unique()->values()->all(),
                'error' => is_string($scan->metadata['error'] ?? null) ? $scan->metadata['error'] : null,
            ])
            ->values()
            ->all();

        return new self(
            period: $period,
            from: $from,
            to: $to,
            counts: $counts,
            averageDurationMs: round(
                (float) SecurityScan::query()->whereBetween('created_at', [$from, $to])->avg('duration_ms'),
                1,
            ),
            topThreats: $topThreats,
            scanners: $scanners,
            incidents: $incidents,
            incidentsTotal: $incidentsTotal,
        );
    }

    public function isQuiet(): bool
    {
        return $this->counts['total'] === 0;
    }

    public function isHealthy(): bool
    {
        return $this->counts['infected'] === 0
            && $this->counts['suspicious'] === 0
            && $this->counts['failed'] === 0;
    }

    /** Scan failures matter on their own: fail-closed means users are blocked. */
    public function hasFailures(): bool
    {
        return $this->counts['failed'] > 0;
    }

    public function hasOfflineScanner(): bool
    {
        // Scanning switched off on purpose (jobly since 2026-09-28, clamd
        // masked) is not an outage — without this the daily mail fires
        // every day about an engine nobody is meant to run.
        if (! (bool) config('content-security.enabled', true)) {
            return false;
        }

        foreach ($this->scanners as $scanner) {
            if ($scanner->isProblem()) {
                return true;
            }
        }

        return false;
    }

    /** Something that needs a human: malware, quarantine or a broken scan. */
    public function needsAction(): bool
    {
        return $this->counts['infected'] + $this->counts['quarantined'] + $this->counts['failed'] > 0
            || $this->hasOfflineScanner();
    }

    /**
     * Whether this digest is worth an email at all. A daily report that says
     * "nothing happened" every day for six months trains its readers to
     * delete it unopened — and then the one that matters is deleted too.
     *
     * Daily: only when something needs action. Suspicious alone is a user
     * uploading the wrong file type (a rejected .bmp), which the weekly
     * covers. Weekly: any week with scans, so a quiet week is confirmed.
     */
    public function worthSending(): bool
    {
        return $this->period === 'weekly' ? ! $this->isQuiet() : $this->needsAction();
    }
}
