# Quarantine

```
upload → quarantine disk → scan → clean ──→ final storage
                                 └ threat → quarantine / delete
```

Unscanned and rejected files never enter normal storage.

## Two rules

**Stored names are generated ULIDs.** The uploader's filename never touches
the path — it is the input that carries traversal sequences, null bytes and
executable extensions. It is kept as metadata, where it can be read but never
obeyed.

**The quarantine disk must not be web-served.** The package cannot enforce
that; `content-security:status` warns when the configured disk looks public.
A web-served quarantine is a malware distribution endpoint.

```php
'storage' => [
    'quarantine_disk' => env('CONTENT_SECURITY_QUARANTINE_DISK', 'local'),
    'quarantine_path' => 'content-security/quarantine',
    'retention_days' => 30,
],
```

## Reject or quarantine

Per policy:

```php
'on_threat' => 'quarantine',   // keep the evidence
'on_threat' => 'reject',       // refuse, keep nothing
```

A **failed** scan is quarantined too. The file is unproven, not proven bad,
and throwing away the one artefact an operator needs to work out why the
scanner broke is the wrong instinct.

## Release

From the console, or:

```php
app(ReleaseQuarantinedFile::class)->handle(
    scan: $scan,
    targetDisk: 'documents',
    targetPath: 'applications/2026/cv.pdf',
    actorId: auth()->id(),
);
```

The file is **rescanned first** and released only if the new scan is clean.
Otherwise `QuarantineException` is thrown.

An override is possible and must be asked for explicitly:

```php
app(ReleaseQuarantinedFile::class)->handle(
    $scan, 'documents', 'path.pdf', auth()->id(), override: true,
);
```

Overrides dispatch `QuarantineReleased` with `overridden: true` and are logged
at warning level whatever the logging config says. This is the one action that
can undo every other control in the package.

The console requires a typed confirmation and a written reason for an
override.

## Rescan

Re-runs the pipeline without releasing anything. Useful after a signature
update: an operator can see that a file now comes back clean without the act
of checking having let it out.

## Delete

Permanent removal of the object. **The scan row is kept** — that a file was
quarantined is the part of the record worth keeping after the file is gone.

The console requires typing `DELETE`.

## Retention

```bash
php artisan content-security:cleanup-quarantine --days=30 --prune-scans
```

Scheduled daily at 03:30 by default. Deletes expired objects and, with
`--prune-scans`, old scan history. Scans that still hold a quarantined file
are never pruned.
