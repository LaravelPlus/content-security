# Reports

```dotenv
CONTENT_SECURITY_REPORT_TO=security@example.com,ops@example.com
CONTENT_SECURITY_REPORT_TIMEZONE=Europe/Ljubljana
```

Both digests schedule themselves once recipients are set. With none
configured, the commands exit quietly — the schedule is safe to leave
registered, and a nightly failure email about a missing email address helps
nobody.

## Daily

07:30 by default, covering yesterday in the reader's timezone.

Sent **only when there is something to say**: findings, scan failures, or an
offline engine. A daily mail that says "nothing happened" every day for six
months trains its readers to delete it unopened, and then the one that matters
is deleted too.

## Weekly

Monday 08:00 by default, covering last week. **Always sent**, so a quiet week
is confirmed rather than merely assumed.

## What's in them

Scan counts by status, malware detections, quarantine, scan failures, average
duration, the ten most frequent findings, and scanner health. Scan failures
get their own warning: with fail-closed on, users are being blocked.

## Manually

```bash
php artisan content-security:report --period=daily --preview     # figures only
php artisan content-security:report --period=weekly --force      # send regardless
php artisan content-security:report --to=me@example.com
```

## Customising

```bash
php artisan vendor:publish --tag=content-security-views
php artisan vendor:publish --tag=content-security-lang
```

The Blade view is `content-security::mail.digest`; `SecurityReport` is the
value object behind it, usable anywhere:

```php
$report = SecurityReport::build('daily', $from, $to, ContentSecurity::health());

$report->counts;
$report->topThreats;
$report->isHealthy();
$report->hasFailures();
```

## Schedules

```php
'reports' => [
    'daily' => ['enabled' => true, 'at' => '07:30'],
    'weekly' => ['enabled' => true, 'day' => 'monday', 'at' => '08:00'],
],

'schedule' => [
    'cleanup_quarantine' => true,
    'cleanup_at' => '03:30',
],
```

All registered with `onOneServer()` and `withoutOverlapping()`.
