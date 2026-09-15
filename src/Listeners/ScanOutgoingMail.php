<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Listeners;

use Illuminate\Log\LogManager;
use Illuminate\Mail\Events\MessageSending;
use LaravelPlus\ContentSecurity\ContentSecurity;

/**
 * Scans every message Laravel is about to send and cancels the ones that are
 * not clean. Returning false from MessageSending is Laravel's own way of
 * stopping a send, so there is no mail pipeline to replace.
 *
 * Fail closed: a scanner that is down stops the mail too. The individual
 * findings are already logged per part; this adds the one line that says a
 * message did not go out.
 */
final readonly class ScanOutgoingMail
{
    public function __construct(
        private ContentSecurity $security,
        private LogManager $log,
    ) {}

    public function handle(MessageSending $event): ?bool
    {
        if (! (bool) config('content-security.mail.scan_outbound', false)) {
            return null;
        }

        $result = $this->security->scanEmail($event->message);

        if ($result->isClean()) {
            // null, not true: `until()` stops at the first non-null answer,
            // and other MessageSending listeners still deserve their turn.
            return null;
        }

        /** @var string|null $channel */
        $channel = config('content-security.logging.channel');

        ($channel === null ? $this->log->driver() : $this->log->channel($channel))
            ->warning('content-security.mail.blocked', [
                'scan_id' => (string) $result->scanId(),
                'status' => $result->status()->value,
                'parts' => array_map(static fn ($check): string => $check->check.'='.$check->status->value, $result->checks()),
            ]);

        return false;
    }
}
