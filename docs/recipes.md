# Recipes

## A job application form

```php
final class StoreApplicationRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'cv' => ['required', 'file', 'mimes:pdf,doc,docx', 'max:10240', new SafeFile('documents')],
            'cover_letter' => ['nullable', 'string', 'max:5000', new SafeText()],
            'portfolio_url' => ['nullable', 'url', app(SafeUrl::class)],
        ];
    }
}
```

## An avatar, re-encoded

```php
'images' => [
    'reencode' => true,
    'strip_metadata' => true,
],
```

```php
'avatar' => ['required', 'image', 'dimensions:max_width=4000', new SafeFile('images')],
```

Re-encoding rewrites the file from decoded pixels, which strips EXIF (location
data included) and anything appended after the last marker. It costs a JPEG
round-trip — deliberate, and worth it for user-supplied avatars.

## Rich text: sanitize, don't reject

```php
$post->body = ContentSecurity::sanitizeHtml($request->string('body'));
```

To also record what was stripped:

```php
$rule = new SafeHtml();
$request->validate(['body' => ['required', $rule]]);

$post->body = $rule->sanitized() ?? '';
```

## Spatie Media Library

```php
$result = ContentSecurity::scanFileOrFail($request->file('document'), 'documents');

$model->addMedia($request->file('document'))
      ->withCustomProperties(['scan_id' => (string) $result->scanId()])
      ->toMediaCollection('documents');
```

Handle `PolicyViolationException` where you render errors:

```php
public function render($request, Throwable $e)
{
    if ($e instanceof PolicyViolationException) {
        return back()->withErrors(['document' => $e->getMessage()]);
    }

    return parent::render($request, $e);
}
```

## S3, private until proven clean

```php
$path = $request->file('doc')->store('pending', 'private');

$result = ContentSecurity::scanDisk('private', $path);

if (! $result->isClean()) {
    Storage::disk('private')->delete($path);

    return back()->withErrors(['doc' => 'This file did not pass a security check.']);
}

Storage::disk('private')->move($path, 'approved/'.basename($path));
```

`scanDisk` streams the object to a bounded temporary file and cleans up after
itself.

## Large uploads

```php
$scanId = ContentSecurity::queue($request->file('video'), 'media');

$upload->update(['scan_id' => (string) $scanId, 'status' => 'scanning']);
```

```php
Event::listen(ScanCompleted::class, function (ScanCompleted $event): void {
    Upload::where('scan_id', (string) $event->result->scanId())
        ->update(['status' => $event->result->isClean() ? 'ready' : 'rejected']);
});
```

## Per-tenant policies

```php
ContentSecurity::resolveFilePolicyUsing(function (string $name): FilePolicy {
    $tenant = Tenant::current();

    return FilePolicy::custom(
        extensions: $tenant->allowed_extensions,
        maxSize: $tenant->max_upload_size,
        overrides: ['label' => "{$tenant->name} uploads"],
    );
});
```

## Tagging scans with the request

```php
ContentSecurity::beforeScan(
    fn (ScanContext $c) => $c->withActor(auth()->id(), request()->header('X-Request-Id')),
);
```

Both land in the audit row and in every log line for that scan.

## Alerting to Slack

```php
Event::listen(ThreatDetected::class, function (ThreatDetected $event): void {
    if (! $event->threat->isAtLeast(ThreatLevel::High)) {
        return;
    }

    Notification::route('slack', config('services.slack.security'))
        ->notify(new ThreatAlert($event->threat, $event->result->scanId()));
});

// The one people forget.
Event::listen(ScanFailed::class, NotifyOpsChannel::class);
```

## Serving approved files safely

```php
Route::get('/documents/{document}', function (Document $document) {
    Gate::authorize('view', $document);

    return Storage::disk('private')->download(
        $document->path,
        $document->original_filename,   // metadata, not the storage path
        ['X-Content-Type-Options' => 'nosniff'],
    );
})->middleware('auth');
```

The stored path is a generated ULID; the original filename is metadata used
only for the `Content-Disposition` header.

## Backfilling existing uploads

```php
Attachment::query()->lazyById(100)->each(function (Attachment $attachment): void {
    $result = ContentSecurity::scanDisk($attachment->disk, $attachment->path);

    $attachment->update([
        'scan_id' => (string) $result->scanId(),
        'scan_status' => $result->status()->value,
    ]);
});
```

Run it before tightening a policy — the Threats page then tells you which
policies are too strict before a user does.
