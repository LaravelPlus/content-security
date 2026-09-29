<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use LaravelPlus\ContentSecurity\Reports\SecurityReport;

/**
 * The daily/weekly digest mail. Rendered from a package Blade view so a
 * host can publish and restyle it.
 */
final class SecurityDigest extends Notification
{
    use Queueable;

    public function __construct(private readonly SecurityReport $report) {}

    /**
     * @return list<string>
     */
    public function via(mixed $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(mixed $notifiable): MailMessage
    {
        $subject = $this->subject();

        return (new MailMessage)
            ->subject($subject)
            ->markdown('content-security::mail.digest', [
                'report' => $this->report,
                'consoleUrl' => $this->consoleUrl(),
            ]);
    }

    /** Verdict plus the one fact that matters: the non-zero counters, worst first. */
    private function subject(): string
    {
        $counts = $this->report->counts;
        $parts = [];

        foreach (['infected', 'failed', 'quarantined', 'suspicious'] as $key) {
            if ($counts[$key] > 0) {
                $parts[] = __("content-security::report.{$key}").' '.$counts[$key];
            }
        }

        if ($this->report->hasOfflineScanner()) {
            $parts[] = __('content-security::report.scanner_offline');
        }

        $verdict = $parts === [] ? __('content-security::report.ok') : implode(', ', $parts);
        $from = $this->report->from;

        return (string) ($this->report->period === 'weekly'
            ? __('content-security::report.weekly_subject', [
                'from' => $from->format('j. n.'),
                'to' => $this->report->to->format('j. n.'),
                'verdict' => $verdict,
            ])
            : __('content-security::report.daily_subject', ['date' => $from->format('j. n.'), 'verdict' => $verdict]));
    }

    private function consoleUrl(): ?string
    {
        if (! (bool) config('content-security.admin.enabled', true)) {
            return null;
        }

        return url((string) config('content-security.admin.prefix', 'admin/content-security'));
    }
}
