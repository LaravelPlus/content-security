# Production checklist

## Before you go live

- [ ] `CONTENT_SECURITY_FAIL_CLOSED=true`. Leave it on.
- [ ] A real malware driver — not `null`.
- [ ] `clamd` running with **current** signatures. `freshclam` on a timer.
      An engine with year-old signatures is theatre.
- [ ] Quarantine disk **not** web-served.
- [ ] Web server configured so uploaded files are never executed.
- [ ] `ContentSecurity::auth()` configured. It denies by default, so an
      unconfigured console is closed, not open.
- [ ] Uploads served through a controller that checks authorization, not by
      the web server from a public directory.
- [ ] `ScanFailed` alerts wired.
- [ ] Report recipients set.
- [ ] Queue workers running for `ContentSecurity::queue()`.
- [ ] `php artisan content-security:status` clean.

```bash
php artisan content-security:status
php artisan content-security:health
```

## Web server

Never execute uploaded content:

```nginx
location ^~ /storage/uploads/ {
    location ~ \.(php|phar|phtml)$ { deny all; }
    add_header X-Content-Type-Options nosniff;
    add_header Content-Disposition "attachment";
}
```

Better: keep uploads outside the web root entirely and serve them through a
controller.

```php
Route::get('/documents/{document}', function (Document $document) {
    Gate::authorize('view', $document);

    return Storage::disk('private')->download(
        $document->path,
        $document->original_filename,
    );
});
```

## ClamAV capacity

`clamd` holds the signature database resident — budget ~1.5 GB. If it gets
OOM-killed, every upload starts failing closed, which users will notice.

Scanning is CPU-bound and roughly linear in file size. For anything above a
few MB, use `ContentSecurity::queue()`.

Keep `StreamMaxLength` in `clamd.conf` at or above the package's
`max_stream_size`.

## Database growth

```php
'persistence' => ['prune_after_days' => 180],
'storage' => ['retention_days' => 30],
```

The daily cleanup handles both. Scans holding a quarantined file are never
pruned.

`content_security_scans` gets one row per scanned item, so a busy upload
endpoint accumulates. The indexes cover the console's access patterns
(status + created_at, type + created_at, checksum, created_at).

## Monitoring

Alert on:

- `ScanFailed` — the engine is down and users are blocked
- an offline scanner in `content-security:health` (non-zero exit)
- `ThreatDetected` at Critical
- `QuarantineReleased` with `overridden: true`
- `PolicyChanged`

## Rollback

```dotenv
CONTENT_SECURITY_ENABLED=false
```

Rules pass everything through; nothing else in your app changes. Tables and
console stay, so the history stays readable.

## What this does not cover

Re-read [security.md](security.md). This layer does not replace authorization,
parameterised queries, output escaping, CSP, CSRF, secure file serving, OS
hardening, or keeping signatures current.
