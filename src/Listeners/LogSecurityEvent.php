<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Listeners;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Log\LogManager;
use LaravelPlus\ContentSecurity\Events\FileQuarantined;
use LaravelPlus\ContentSecurity\Events\PolicyChanged;
use LaravelPlus\ContentSecurity\Events\QuarantineDeleted;
use LaravelPlus\ContentSecurity\Events\QuarantineReleased;
use LaravelPlus\ContentSecurity\Events\ScanCompleted;
use LaravelPlus\ContentSecurity\Events\ScanFailed;
use LaravelPlus\ContentSecurity\Events\ThreatDetected;
use Psr\Log\LoggerInterface;

/**
 * Structured logging for every security event.
 *
 * What is logged: identifiers, verdicts, timings, counts. What is never
 * logged: file contents, scanned text, matched payloads, filesystem paths
 * outside the quarantine root. A log line that quotes the payload has moved
 * the attack into a system that is usually shipped somewhere else and read
 * by more people.
 */
final readonly class LogSecurityEvent
{
    public function __construct(private LogManager $log) {}

    public function subscribe(Dispatcher $events): void
    {
        $events->listen(ScanCompleted::class, $this->onScanCompleted(...));
        $events->listen(ScanFailed::class, $this->onScanFailed(...));
        $events->listen(ThreatDetected::class, $this->onThreatDetected(...));
        $events->listen(FileQuarantined::class, $this->onFileQuarantined(...));
        $events->listen(QuarantineReleased::class, $this->onQuarantineReleased(...));
        $events->listen(QuarantineDeleted::class, $this->onQuarantineDeleted(...));
        $events->listen(PolicyChanged::class, $this->onPolicyChanged(...));
    }

    public function onScanCompleted(ScanCompleted $event): void
    {
        if (! $this->enabled()) {
            return;
        }

        $this->channel()->log($this->level(), 'content-security.scan.completed', [
            'scan_id' => (string) $event->result->scanId(),
            'request_id' => $event->context->requestId,
            'type' => $event->result->type()->value,
            'policy' => $event->context->policy,
            'status' => $event->result->status()->value,
            'scanner' => $event->result->scanner(),
            'duration_ms' => round($event->result->duration(), 2),
            'threat_count' => count($event->result->threats()),
        ]);
    }

    public function onScanFailed(ScanFailed $event): void
    {
        if (! $this->enabled()) {
            return;
        }

        // Always at warning or above: a fail-closed application with a
        // broken scanner is rejecting every upload, and that must not be
        // buried at info level.
        $this->channel()->warning('content-security.scan.failed', [
            'scan_id' => (string) $event->result->scanId(),
            'request_id' => $event->context->requestId,
            'type' => $event->result->type()->value,
            'reason' => $event->reason,
        ]);
    }

    public function onThreatDetected(ThreatDetected $event): void
    {
        if (! $this->enabled()) {
            return;
        }

        $this->channel()->log($this->threatLevel(), 'content-security.threat.detected', [
            'scan_id' => (string) $event->result->scanId(),
            'request_id' => $event->context->requestId,
            'threat' => $event->threat->name,
            'level' => $event->threat->level->value,
            'source' => $event->threat->source,
            'user_id' => $event->context->userId,
        ]);
    }

    public function onFileQuarantined(FileQuarantined $event): void
    {
        if (! $this->enabled()) {
            return;
        }

        $this->channel()->warning('content-security.file.quarantined', [
            'scan_id' => (string) $event->scanId,
            'disk' => $event->disk,
            // The path is a generated ULID under the quarantine root — it
            // reveals nothing about the uploader or the original filename.
            'path' => $event->path,
        ]);
    }

    public function onQuarantineReleased(QuarantineReleased $event): void
    {
        // Logged whatever the config says. Releasing a quarantined file is
        // the one action here that can undo every other control, and an
        // override is the single most audit-worthy thing this package does.
        $this->channel()->warning('content-security.quarantine.released', [
            'scan_id' => (string) $event->scanId,
            'target_disk' => $event->targetDisk,
            'actor_id' => $event->actorId,
            'override' => $event->overridden,
        ]);
    }

    public function onQuarantineDeleted(QuarantineDeleted $event): void
    {
        $this->channel()->warning('content-security.quarantine.deleted', [
            'scan_id' => (string) $event->scanId,
            'actor_id' => $event->actorId,
        ]);
    }

    /**
     * Always logged, config regardless. Changing a security policy at
     * runtime is exactly the kind of thing someone needs to be able to
     * reconstruct six months later — including what it was before.
     */
    public function onPolicyChanged(PolicyChanged $event): void
    {
        $this->channel()->warning('content-security.policy.changed', [
            'type' => $event->type,
            'policy' => $event->name,
            'changed' => $event->changedKeys(),
            'before' => $event->before,
            'after' => $event->after,
            'actor_id' => $event->actorId,
            'note' => $event->note,
        ]);
    }

    private function enabled(): bool
    {
        return (bool) config('content-security.logging.enabled', true);
    }

    private function channel(): LoggerInterface
    {
        /** @var string|null $channel */
        $channel = config('content-security.logging.channel');

        return $channel === null ? $this->log->driver() : $this->log->channel($channel);
    }

    private function level(): string
    {
        return (string) config('content-security.logging.level', 'info');
    }

    private function threatLevel(): string
    {
        return (string) config('content-security.logging.threat_level', 'warning');
    }
}
