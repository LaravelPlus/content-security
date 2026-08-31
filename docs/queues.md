# Queued scanning

Scanning a 500 MB upload inside a request cycle will not end well.

```php
$scanId = ContentSecurity::queue($request->file('video'));

$submission->update([
    'scan_id' => (string) $scanId,
    'status' => 'scanning',
]);
```

## What happens

1. The file is written to the **quarantine disk immediately**, under a
   generated ULID.
2. `ScanFileJob` is dispatched with that scan id, disk and path.
3. A worker runs the same pipeline and updates the same audit row.

The order is the point: an unscanned upload must never sit in normal storage
waiting to be judged.

## Reacting to the outcome

```php
Event::listen(ScanCompleted::class, function (ScanCompleted $event): void {
    $submission = Submission::where('scan_id', (string) $event->result->scanId())->first();

    if ($submission === null) {
        return;
    }

    $submission->update([
        'status' => $event->result->isClean() ? 'ready' : 'rejected',
    ]);
});
```

Or poll:

```php
$scan = app(ScanRepository::class)->find(ScanId::fromString($submission->scan_id));

$scan?->status;   // ScanStatus enum
```

## Reliability

```php
'queue' => [
    'connection' => env('CONTENT_SECURITY_QUEUE_CONNECTION'),
    'queue' => env('CONTENT_SECURITY_QUEUE', 'default'),
    'tries' => 3,
    'timeout' => 300,
    'backoff' => [10, 60, 300],
],
```

- **Idempotent.** The scan id is fixed by the caller, so a retry updates the
  audit row rather than creating a second one.
- **Small payloads.** The job carries a disk and a path, never file contents.
- **Terminal failure is recorded.** When retries are exhausted the row is
  marked `failed`. A row left saying "scanning" for ever is a scan your
  application can never treat as failed, which defeats fail-closed.

## Isolation

Give scanning its own queue and its own workers. Malformed input is the normal
case here, and you do not want a pathological archive delaying your password
reset emails.

```bash
php artisan queue:work --queue=content-security --timeout=320
```

Set the worker `--timeout` above the job timeout, or the worker kills the job
before the job can fail cleanly.
