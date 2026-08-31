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
     */
    public function __construct(
        public string $period,
        public CarbonImmutable $from,
        public CarbonImmutable $to,
        public array $counts,
        public float $averageDurationMs,
        public array $topThreats,
        public array $scanners,
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
        foreach ($this->scanners as $scanner) {
            if ($scanner->enabled && ! $scanner->online) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether this digest is worth an email at all. A daily report that says
     * "nothing happened" every day for six months trains its readers to
     * delete it unopened — and then the one that matters is deleted too.
     */
    public function worthSending(): bool
    {
        return ! $this->isQuiet()
            && (! $this->isHealthy() || $this->hasOfflineScanner() || $this->period === 'weekly');
    }
}
