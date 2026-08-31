<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Console\Commands;

use Carbon\CarbonImmutable;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Notification;
use LaravelPlus\ContentSecurity\ContentSecurity;
use LaravelPlus\ContentSecurity\Notifications\SecurityDigest;
use LaravelPlus\ContentSecurity\Reports\SecurityReport;

/**
 * Daily and weekly digests.
 *
 * Scheduled from the service provider when recipients are configured. Both
 * periods share one command because they share every line of their logic —
 * only the window differs.
 */
final class ReportCommand extends Command
{
    protected $signature = 'content-security:report
        {--period=daily : daily or weekly}
        {--to=* : Override the configured recipients}
        {--force : Send even when there is nothing to report}
        {--preview : Print the figures instead of sending}';

    protected $description = 'Send the daily or weekly content security digest.';

    public function handle(ContentSecurity $security): int
    {
        $period = is_string($this->option('period')) ? $this->option('period') : 'daily';

        if (! in_array($period, ['daily', 'weekly'], true)) {
            $this->components->error('--period must be daily or weekly.');

            return self::FAILURE;
        }

        $timezone = (string) config('content-security.reports.timezone', config('app.timezone', 'UTC'));
        $now = CarbonImmutable::now($timezone);

        // Yesterday, or last week — a report sent at 07:30 covers a period
        // that has actually ended, in the reader's own timezone.
        [$from, $to] = $period === 'weekly'
            ? [$now->subWeek()->startOfWeek(), $now->subWeek()->endOfWeek()]
            : [$now->subDay()->startOfDay(), $now->subDay()->endOfDay()];

        $report = SecurityReport::build($period, $from, $to, $security->health());

        if ($this->option('preview')) {
            $this->preview($report);

            return self::SUCCESS;
        }

        $recipients = $this->recipients();

        if ($recipients === []) {
            // Quiet, not an error: the schedule is registered whether or not
            // anyone has configured a recipient yet, and a nightly failure
            // email about a missing email address helps nobody.
            $this->components->info('No recipients configured; nothing sent.');

            return self::SUCCESS;
        }

        if (! $this->option('force') && ! $report->worthSending()) {
            $this->components->info('Nothing worth reporting for this period.');

            return self::SUCCESS;
        }

        Notification::route('mail', $recipients)->notify(new SecurityDigest($report));

        $this->components->info(sprintf(
            'Sent the %s report to %s.',
            $period,
            implode(', ', $recipients),
        ));

        return self::SUCCESS;
    }

    /**
     * @return list<string>
     */
    private function recipients(): array
    {
        /** @var list<string> $option */
        $option = (array) $this->option('to');

        if ($option !== []) {
            return array_values(array_filter($option));
        }

        /** @var list<string>|string|null $configured */
        $configured = config('content-security.reports.recipients');

        if (is_string($configured)) {
            $configured = array_map(trim(...), explode(',', $configured));
        }

        return array_values(array_filter((array) $configured));
    }

    private function preview(SecurityReport $report): void
    {
        $this->components->info(sprintf(
            '%s report: %s → %s',
            ucfirst($report->period),
            $report->from->toDateTimeString(),
            $report->to->toDateTimeString(),
        ));

        foreach ($report->counts as $key => $value) {
            $this->components->twoColumnDetail(str_replace('_', ' ', $key), (string) $value);
        }

        $this->components->twoColumnDetail('avg duration', sprintf('%.1f ms', $report->averageDurationMs));
        $this->components->twoColumnDetail('worth sending', $report->worthSending() ? 'yes' : 'no');

        if ($report->topThreats !== []) {
            $this->newLine();
            $this->table(
                ['Threat', 'Level', 'Occurrences'],
                array_map(static fn (array $t): array => [$t['name'], $t['level'], (string) $t['occurrences']], $report->topThreats),
            );
        }
    }
}
