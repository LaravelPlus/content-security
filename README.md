# Content Security

[![Latest Version on Packagist](https://img.shields.io/packagist/v/laravelplus/content-security.svg?style=flat-square)](https://packagist.org/packages/laravelplus/content-security)
[![Total Downloads](https://img.shields.io/packagist/dt/laravelplus/content-security.svg?style=flat-square)](https://packagist.org/packages/laravelplus/content-security)
[![Tests](https://img.shields.io/github/actions/workflow/status/LaravelPlus/content-security/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/LaravelPlus/content-security/actions)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%208-brightgreen.svg?style=flat-square)](https://phpstan.org/)
[![PHP Version](https://img.shields.io/packagist/dependency-v/laravelplus/content-security/php?style=flat-square)](https://www.php.net/)
[![Laravel Version](https://img.shields.io/badge/Laravel-13.x-FF2D20.svg?style=flat-square&logo=laravel)](https://laravel.com/)
[![License](https://img.shields.io/packagist/l/laravelplus/content-security.svg?style=flat-square)](LICENSE)

A defence-in-depth content security layer for Laravel: malware scanning, MIME
and magic-byte verification, archive/image/PDF inspection, HTML sanitization,
URL and SSRF checks, quarantine, a full audit trail, and a Vue 3 security
console at `/admin/content-security`.

```php
use LaravelPlus\ContentSecurity\Rules\SafeFile;

$request->validate([
    'attachment' => ['required', 'file', new SafeFile()],
]);
```

```php
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;

$result = ContentSecurity::scanFile($file);

if ($result->isClean()) {
    // accept
}
```

---

## What this is, and what it is not

**Content Security is one layer.** It does not replace, and must not be
described as replacing:

- proper authorization
- Laravel's own validation
- parameterised SQL queries — an ORM or query bindings
- contextual output escaping
- a Content-Security-Policy header
- CSRF protection
- serving uploads from outside the web root
- OS and container hardening
- keeping malware signatures up to date

Two specific claims this package explicitly does **not** make:

**It does not prevent SQL injection.** Parameterised queries do. The
suspicious-content scanner recognises some payload *shapes*, which is useful
as an alerting signal — "someone just pasted a `UNION SELECT` into a job
description" — and useless as a control. A codebase that concatenates user
input into SQL is not made safe by installing this.

**It does not prevent XSS on its own.** Contextual output escaping does.
What this package adds is a real HTML sanitizer (a parser, never a regex) for
the cases where you must accept and re-render untrusted markup.

And no file is ever "100% safe". A clean scan means no configured check
objected — not that the file is harmless.

---

## Requirements

- PHP 8.5+
- Laravel 13
- `ext-fileinfo` (required), `ext-zip` (archives), `ext-gd` (images)
- ClamAV `clamd` for malware scanning — optional but strongly recommended
- `inertiajs/inertia-laravel` for the admin console

## Installation

```bash
composer require laravelplus/content-security
php artisan content-security:install
php artisan migrate
```

Then tell the package who may open the console — it denies everyone until
you do:

```php
// AppServiceProvider::boot()
ContentSecurity::auth(fn (User $user): bool => $user->isAdmin());
```

Check the wiring:

```bash
php artisan content-security:status
```

### ClamAV

```bash
# Debian / Ubuntu
sudo apt install clamav clamav-daemon
sudo systemctl enable --now clamav-freshclam clamav-daemon
```

```dotenv
CONTENT_SECURITY_CLAMAV_CONNECTION=unix
CONTENT_SECURITY_CLAMAV_SOCKET=/var/run/clamav/clamd.ctl
```

The package talks to the resident `clamd` daemon rather than spawning
`clamscan` per upload — the binary reloads the entire signature database on
every invocation, which is roughly a second of CPU and several hundred MB of
RAM each time.

Verify from the console (**Scanner health → Test scanner**) or:

```bash
php artisan content-security:health
```

---

## Fail closed

This is the single most important behaviour in the package.

When a scanner cannot answer — the daemon is down, the socket times out, the
file is unreadable — the scan is reported as **failed**, and a failed scan is
**not clean**:

```php
$result->isClean();  // false
$result->failed();   // true
$result->isThreat(); // false — nothing was found, because nothing looked
```

`failed()` is deliberately not the opposite of `isThreat()`. "We looked and
found nothing" and "we could not look" are different facts, and a system that
conflates them accepts every upload the moment its scanner falls over.

Set `fail_closed => false` only if you have thought hard about it.

---

## Scanning

```php
ContentSecurity::scanFile($uploadedFile);              // default policy
ContentSecurity::scanFile($uploadedFile, 'images');    // named policy
ContentSecurity::scanFile('/path/to/file.pdf');
ContentSecurity::scanDisk('s3', 'uploads/report.pdf');
ContentSecurity::scanFileOrFail($file);                // throws PolicyViolationException

ContentSecurity::scanText($comment);
ContentSecurity::scanHtml($richText);
ContentSecurity::sanitizeHtml($richText);              // returns clean HTML
ContentSecurity::scanUrl($website);
ContentSecurity::queue($largeFile);                    // returns a ScanId
```

### The result

```php
$result->isClean();
$result->isThreat();
$result->isInfected();
$result->failed();
$result->status();              // ScanStatus enum
$result->threats();             // list<Threat>
$result->checks();              // per-check outcomes
$result->duration();            // milliseconds
$result->scanner();
$result->scanId();
$result->metadata();
$result->highestThreatLevel();
```

### The file pipeline

Cheapest first, so an obviously bad upload never reaches the engine:

```
size → extension → MIME → magic bytes → archive → image → PDF → malware
```

Every step is switchable per policy, and a step that is switched off is
recorded as *skipped* rather than omitted — a disabled malware scan must
never look identical to a passing one.

---

## Validation rules

```php
$request->validate([
    'attachment'  => ['nullable', 'file', new SafeFile()],
    'avatar'      => ['nullable', 'image', new SafeFile('images')],
    'description' => ['required', new SafeHtml()],
    'bio'         => ['required', 'string', new SafeText()],
    'website'     => ['nullable', new SafeUrl()],
]);
```

User-facing messages are deliberately vague ("This file did not pass a
security check"). Naming the signature or the check would turn the endpoint
into a free malware sandbox that tells an attacker which attempt got closest.
The full detail goes to the audit log and the console.

The developer-facing detail is available on the rule:

```php
$rule = new SafeFile();
$request->validate(['attachment' => ['required', 'file', $rule]]);

$rule->result()->scanId();  // store it against your own model
```

For rich text, consider sanitizing instead of rejecting:

```php
$post->body = ContentSecurity::sanitizeHtml($request->string('body'));
```

---

## Quarantine

```
upload → quarantine disk → scan → clean ──→ final storage
                                 └ threat → quarantine / delete
```

Unscanned and rejected files never touch normal storage. Stored filenames are
generated ULIDs — the uploader's filename is kept as metadata, where it can
be read but never obeyed.

```php
'storage' => [
    'quarantine_disk' => 'local',   // MUST NOT be web-served
    'quarantine_path' => 'content-security/quarantine',
],
```

Releasing a file rescans it first and proceeds only on a clean result. An
override is possible, must be asked for explicitly, and is dispatched as an
audited event.

---

## Policies

`config/content-security.php` is the baseline. With `admin.manage_policies`
on, the database holds *overrides* on top of it, edited from the console and
recorded in the audit log. A policy nobody has touched has no row at all and
reads straight from config, so your deployment defaults stay the reviewed,
version-controlled thing they should be — and **Reset** always means
something.

Two things are never overridable at runtime, enforced in the repository
rather than in the UI:

- `forbidden_extensions` — the server-executable formats. A console that
  could add `php` to an allowlist would *be* the vulnerability.
- the `max_size_ceiling`.

Set `CONTENT_SECURITY_MANAGE_POLICIES=false` for installations that want
their security policy reviewable in a diff and nowhere else.

---

## Admin console

Mounted at `/admin/content-security` (configurable via
`content-security.admin.prefix` or `CONTENT_SECURITY_ADMIN_PREFIX`).

Overview · Scans · Threats · Quarantine · Policies · Scanner health

```bash
php artisan content-security:publish-pages
npm run build
```

If your app maps Inertia pages to layouts, exclude the console — it ships its
own full-page shell:

```ts
case name.startsWith('admin/content-security/'):
    return undefined;
```

Authorization is entirely yours. The package denies by default: no callback
and no gate means nobody gets in, and unauthorised visitors get a 404 rather
than a 403, because confirming that a security console exists at this URL is
itself information they should not have.

---

## Reports

A daily digest and a weekly roll-up:

```dotenv
CONTENT_SECURITY_REPORT_TO=security@example.com
```

Both are scheduled automatically once recipients are set. The daily mail is
sent only when there is something to say — findings, scan failures, or an
offline engine. The weekly one always goes out, so a quiet week is confirmed
rather than assumed. A digest that says "nothing happened" every day for six
months trains its readers to delete it unopened, and then the one that
matters is deleted too.

```bash
php artisan content-security:report --period=weekly --preview
```

---

## Events

```php
Event::listen(ThreatDetected::class, SendSecurityAlert::class);
```

`ScanStarted` · `ScanCompleted` · `ScanFailed` · `ThreatDetected` ·
`FileQuarantined` · `QuarantineReleased` · `QuarantineDeleted` ·
`PolicyChanged`

`ScanFailed` deserves an alert of its own: a fail-closed application with a
broken scanner is rejecting every upload.

---

## Extending

```php
// A different malware engine
ContentSecurity::extend('yara', fn ($app, $config) => new YaraScanner($config));

// Your own checks
ContentSecurity::addFileCheck(WatermarkCheck::class, before: MalwareCheck::class);
ContentSecurity::addTextCheck(ProfanityCheck::class);

// Hooks into the middle of a scan
ContentSecurity::beforeScan(fn ($context) => $context->withActor(auth()->id()));
ContentSecurity::afterScan(fn ($result, $context) => $result);

// Policies from your own store
ContentSecurity::resolveFilePolicyUsing(fn (string $name) => $tenant->policy($name));
```

Every collaborator is bound to a contract — `MalwareScanner`, `Sanitizer`,
`ArchiveInspector`, `ImageInspector`, `PdfInspector`, `UrlInspector`,
`ScanRepository`, `PolicyRepository` — so any of them can be replaced from
your own service provider without forking the package.

See [docs/extending.md](docs/extending.md).

---

## Commands

```bash
php artisan content-security:status               # config, engines, recent activity
php artisan content-security:scan file.pdf        # exit 0 clean, 1 otherwise
php artisan content-security:health               # exit non-zero if an engine is down
php artisan content-security:report --period=daily
php artisan content-security:cleanup-quarantine
php artisan content-security:install
php artisan content-security:publish-pages
```

---

## Privacy

Scanned text is never stored by default — the audit row keeps a SHA-256 and a
length. Threat metadata never carries the matched payload, and log lines never
carry file contents, scanned text, or filesystem paths outside the quarantine
root. Opt in to short samples with `persistence.store_text_samples`.

---

## Production notes

- Keep the quarantine disk off the web root. `content-security:status` warns
  if it looks publicly served.
- Configure your web server so uploaded files are never executed.
- Run `freshclam` — an engine with year-old signatures is theatre.
- Use `ContentSecurity::queue()` for large files; scanning a 500 MB upload
  inside a request cycle will not end well.
- Alert on `ScanFailed`, not only on `ThreatDetected`.
- Leave `fail_closed` on.

## Testing

```bash
composer test      # Pest
composer analyse   # PHPStan level 8
composer lint      # Pint
```

The suite never requires ClamAV — use `FakeMalwareScanner`. Integration tests
against a real daemon live in the separate `Integration` suite.

## Security

Please report vulnerabilities per [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Credits

[Nejc Cotič](https://github.com/nejcc)

## License

MIT. See [LICENSE](LICENSE).
