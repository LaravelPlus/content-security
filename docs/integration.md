# Integrating into an existing Laravel application

This is the page to follow if you already have an app with uploads in it.
It assumes Laravel 13 and PHP 8.5.

The order matters: get scanning working on one endpoint, prove it, then widen.
Turning it on everywhere at once means every unrelated upload bug looks like a
content-security bug.

---

## 1. Install

```bash
composer require laravelplus/content-security
php artisan content-security:install
php artisan migrate
```

`install` publishes the config and migrations. It does not run migrations,
touch your `.env`, or change anything else — an install command that alters a
production database because someone typed it to see what it did is not a
helpful install command.

Two tables are added: `content_security_scans` and
`content_security_threats` (plus `content_security_policies` if you enable
runtime policy editing).

## 2. Start with no engine

In local and CI, run without ClamAV:

```dotenv
CONTENT_SECURITY_MALWARE_DRIVER=none
```

The `none` driver reports every file as **skipped**, never as clean — so a
development machine cannot tell itself its uploads were checked. Everything
else in the pipeline (extension, MIME, magic bytes, archives, images, PDFs)
still runs, and that is most of the value.

## 3. Wire authorization

The console denies everyone until you say otherwise. In a service provider:

```php
use App\Models\User;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;

public function boot(): void
{
    ContentSecurity::auth(fn (?User $user): bool => $user?->isAdmin() ?? false);
}
```

With `spatie/laravel-permission`:

```php
ContentSecurity::auth(
    fn (?User $user): bool => $user?->hasAnyRole(['admin', 'super-admin']) ?? false,
);
```

Or point it at a Gate ability you already have:

```php
// config/content-security.php
'admin' => ['gate' => 'viewSecurityConsole'],
```

Match the surrounding console's middleware while you are in the config:

```php
'middleware' => ['web', 'auth', 'verified', 'role:admin|super-admin'],
```

## 4. Publish the console

```bash
php artisan content-security:publish-pages
npm run build
```

The Vue pages land in `resources/js/pages/admin/content-security`, which is
where your Vite build already looks for Inertia pages.

If your app maps page names to persistent layouts, exclude these — the
console ships its own full-page shell, and without this you get a shell
inside a shell:

```ts
// resources/js/lib/resolveLayout.ts (or wherever your resolver lives)
case name.startsWith('admin/content-security/'):
    return undefined;
```

Visit `/admin/content-security`. The prefix is configurable:

```dotenv
CONTENT_SECURITY_ADMIN_PREFIX=admin/security
```

## 5. Protect one endpoint

Pick the upload that worries you most and add the rule:

```php
use LaravelPlus\ContentSecurity\Rules\SafeFile;

public function rules(): array
{
    return [
        'cv' => ['required', 'file', 'max:10240', new SafeFile('documents')],
    ];
}
```

Keep Laravel's own `file`, `image` and `max` rules. They are cheaper and they
produce better messages; `SafeFile` is the layer behind them, not a
replacement for them.

Upload something, then open the console. You should see the scan, its
per-check breakdown, and its timing.

## 6. Check what your existing uploads would do

Before widening, find out whether your real traffic passes. Scan what you
already have:

```php
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;

Attachment::query()->lazyById(100)->each(function (Attachment $attachment): void {
    $result = ContentSecurity::scanDisk($attachment->disk, $attachment->path);

    if (! $result->isClean()) {
        logger()->warning('content-security backfill', [
            'attachment' => $attachment->id,
            'status' => $result->status()->value,
            'threats' => array_map(fn ($t) => $t->name, $result->threats()),
        ]);
    }
});
```

Run it in `tinker` or a one-off command. The Threats page then tells you
which policies are too tight before a user finds out for you.

Common surprises, all of them legitimate findings:

| Finding | Usually means |
| --- | --- |
| `file.mime_extension_mismatch` | A `.doc` that is really an RTF, or a `.jpg` that is really a PNG. Widen the policy or fix the upload path. |
| `pdf.no_eof_marker` | A truncated PDF, often from a broken export. |
| `pdf.javascript` | Interactive forms. Common in real documents — decide deliberately. |
| `file.multiple_extensions` | `report.final.pdf`. Low severity; still worth seeing. |
| `archive.executable_entry` | Someone zipped an installer. |

## 7. Add the engine

Once the pipeline fits your traffic, install ClamAV:

```bash
sudo apt install clamav clamav-daemon
sudo systemctl enable --now clamav-freshclam clamav-daemon
```

```dotenv
CONTENT_SECURITY_MALWARE_DRIVER=clamav
CONTENT_SECURITY_CLAMAV_CONNECTION=unix
CONTENT_SECURITY_CLAMAV_SOCKET=/var/run/clamav/clamd.ctl
```

```bash
php artisan content-security:health
```

In Docker, run `clamav/clamav` as its own service and use TCP:

```dotenv
CONTENT_SECURITY_CLAMAV_CONNECTION=tcp
CONTENT_SECURITY_CLAMAV_HOST=clamav
CONTENT_SECURITY_CLAMAV_PORT=3310
```

Give it memory. `clamd` holds the signature database resident — budget
around 1.5 GB, or it will be OOM-killed and every upload will start failing
closed.

### Before you turn it on in production

Understand what fail-closed means for you: **if `clamd` goes down, every
upload is rejected.** That is the correct behaviour, and it is a behaviour you
should find out about from an alert rather than from a customer:

```php
Event::listen(ScanFailed::class, NotifyOpsChannel::class);
```

## 8. Move large files off the request cycle

```php
$scanId = ContentSecurity::queue($request->file('video'));

$submission->update([
    'scan_id' => (string) $scanId,
    'status' => 'scanning',
]);
```

The file goes to the quarantine disk *first*, then a worker scans it. Nothing
unscanned ever waits in normal storage. Listen for `ScanCompleted` to move it
onward.

See [queues.md](queues.md).

## 9. Text and rich text

```php
'bio' => ['required', 'string', new SafeText()],
```

For rich text, prefer sanitizing over rejecting:

```php
$post->body = ContentSecurity::sanitizeHtml($request->string('body'));
```

Rejecting tells someone pasting from Word that their input is "unsafe";
sanitizing quietly removes the `<o:p>` tags. Reach for `SafeHtml` when
unexpected markup is itself the signal you want to act on.

Read [text-and-html.md](text-and-html.md) before relying on `SafeText` for
anything. It is a heuristic tripwire, not a control.

## 10. Operational wiring

```dotenv
CONTENT_SECURITY_REPORT_TO=security@example.com
```

Schedules register themselves — the daily digest, the weekly roll-up, and
quarantine cleanup. All you need is a working scheduler.

Add the health command to your deployment smoke test:

```bash
php artisan content-security:status
php artisan content-security:health
```

---

## Integrating with what you already use

### Spatie Media Library

Scan before the file becomes a media item:

```php
$result = ContentSecurity::scanFileOrFail($request->file('document'), 'documents');

$model->addMedia($request->file('document'))
      ->withCustomProperties(['scan_id' => (string) $result->scanId()])
      ->toMediaCollection('documents');
```

`scanFileOrFail` throws `PolicyViolationException`, which carries the result.
Catch it where you render the error.

### Livewire

```php
public function save(): void
{
    $this->validate([
        'upload' => ['required', 'file', new SafeFile()],
    ]);
}
```

Livewire's temporary uploads are real files on disk, so the rule works
unchanged. Note that the file has already been written to your temporary
disk by then — keep that disk out of the web root.

### Filament / Nova

Both accept standard validation rules on their file fields:

```php
FileUpload::make('attachment')->rules([new SafeFile('documents')]);
```

### S3

Scan before the object is public:

```php
$path = $request->file('doc')->store('pending', 'private');

if (! ContentSecurity::scanDisk('private', $path)->isClean()) {
    Storage::disk('private')->delete($path);
    abort(422);
}

Storage::disk('private')->move($path, "public/{$path}");
```

`scanDisk` streams the object to a bounded temporary file, scans it, and
cleans up after itself.

### An existing admin layout

The console is deliberately standalone. If you want it inside your own
chrome, publish the pages and edit
`resources/js/pages/admin/content-security/layouts/SecurityAdminLayout.vue` —
it is yours once published.

---

## Rollback

Nothing here is load-bearing until you make it so:

```dotenv
CONTENT_SECURITY_ENABLED=false
```

Every validation rule passes everything through, scanning stops, and the rest
of your application is unaffected. The tables and the console stay, so the
history remains readable.
