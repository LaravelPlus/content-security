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
        $subject = $this->report->period === 'weekly'
            ? __('content-security::report.weekly_subject', [
                'from' => $this->report->from->toFormattedDateString(),
                'to' => $this->report->to->toFormattedDateString(),
            ])
            : __('content-security::report.daily_subject', [
                'date' => $this->report->from->toFormattedDateString(),
            ]);

        return (new MailMessage)
            ->subject((string) $subject)
            ->view('content-security::mail.digest', [
                'report' => $this->report,
                'consoleUrl' => $this->consoleUrl(),
            ]);
    }

    private function consoleUrl(): ?string
    {
        if (! (bool) config('content-security.admin.enabled', true)) {
            return null;
        }

        return url((string) config('content-security.admin.prefix', 'admin/content-security'));
    }
}
