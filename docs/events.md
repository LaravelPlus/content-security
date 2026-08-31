# Events

```php
use LaravelPlus\ContentSecurity\Events\{
    ScanStarted, ScanCompleted, ScanFailed, ThreatDetected,
    FileQuarantined, QuarantineReleased, QuarantineDeleted, PolicyChanged,
};

Event::listen(ThreatDetected::class, SendSecurityAlert::class);
```

| Event | Fired when | Carries |
| --- | --- | --- |
| `ScanStarted` | A scan begins | `ScanContext` |
| `ScanCompleted` | Any scan ends, clean or not | `ScanResult`, `ScanContext` |
| `ScanFailed` | A scan could not complete | `ScanResult`, `ScanContext`, reason |
| `ThreatDetected` | Per finding | `Threat`, `ScanResult`, `ScanContext` |
| `FileQuarantined` | A file was moved to quarantine | scan id, disk, path |
| `QuarantineReleased` | A file was let back out | target, actor, `overridden` |
| `QuarantineDeleted` | A quarantined file was erased | scan id, actor |
| `PolicyChanged` | A runtime policy override changed | type, name, before, after, actor, note |

`ThreatDetected` fires once per finding, not once per scan — a listener that
pages someone wants the finding, not a bag of them.

## Alert on failures too

```php
Event::listen(ScanFailed::class, function (ScanFailed $event): void {
    Notification::route('slack', config('services.slack.security'))
        ->notify(new ScannerDown($event->reason));
});
```

A fail-closed application with a broken scanner is rejecting every upload.
That is worse for your users than a detection, and it is silent unless you
listen for it.

## Built-in logging

`LogSecurityEvent` subscribes automatically. Structured, and deliberately
narrow about what it records:

```json
{
  "scan_id": "01JQ…",
  "request_id": null,
  "type": "file",
  "status": "quarantined",
  "scanner": "file-pipeline",
  "duration_ms": 41.2,
  "threat_count": 1
}
```

Never logged: file contents, scanned text, matched payloads, or filesystem
paths outside the quarantine root. A log line that quotes the payload has
moved the attack into a system that is usually shipped elsewhere and read by
more people.

Quarantine releases, deletions and policy changes are logged at warning level
whatever `logging.enabled` says.

```php
'logging' => [
    'enabled' => true,
    'channel' => env('CONTENT_SECURITY_LOG_CHANNEL'),
    'level' => 'info',
    'threat_level' => 'warning',
],
```
