<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Listeners;

use Illuminate\Support\Facades\Notification;
use LaravelPlus\ContentSecurity\Domain\Policy\FindingNotify;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Events\ScanCompleted;
use LaravelPlus\ContentSecurity\Notifications\FindingAlert;
use LaravelPlus\ContentSecurity\Support\ReportRecipients;
use Throwable;

/**
 * Mails findings whose rule asks for `notify: immediate`, once per scan
 * however many of them fired.
 */
final class SendFindingAlerts
{
    public function handle(ScanCompleted $event): void
    {
        $codes = array_values(array_unique(array_map(
            static fn (Threat $threat): string => $threat->name,
            array_filter(
                $event->result->threats(),
                static fn (Threat $threat): bool => ($threat->metadata['notify'] ?? null) === FindingNotify::Immediate->value,
            ),
        )));

        $recipients = ReportRecipients::configured();

        if ($codes === [] || $recipients === []) {
            return;
        }

        try {
            Notification::route('mail', $recipients)->notify(new FindingAlert($event->result, $codes));
        } catch (Throwable $e) {
            // A mail outage must not turn into a failed upload; the finding
            // is already recorded and still reaches the digest.
            report($e);
        }
    }
}
