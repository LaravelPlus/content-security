<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;

/**
 * One mail per scan for findings whose rule says `notify: immediate`.
 * Carries codes and the verdict only, never the file name or contents.
 */
final class FindingAlert extends Notification
{
    use Queueable;

    /** @param  list<string>  $codes */
    public function __construct(private readonly ScanResult $result, private readonly array $codes) {}

    /** @return list<string> */
    public function via(mixed $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(mixed $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject(sprintf('Content security alert: %s', implode(', ', $this->codes)))
            ->line(sprintf('Scan %s finished as %s.', $this->result->scanId(), $this->result->status()->value))
            ->line('Findings: '.implode(', ', $this->codes));
    }
}
