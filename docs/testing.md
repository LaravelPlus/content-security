# Testing your integration

## Never require ClamAV

Your suite must pass on a machine with no daemon. Swap the engine:

```php
use LaravelPlus\ContentSecurity\Contracts\MalwareScanner;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;

ContentSecurity::extend('clamav', fn () => FakeMalwareScanner::clean());
config()->set('content-security.malware.default', 'clamav');
```

Or set `CONTENT_SECURITY_MALWARE_DRIVER=none` in `phpunit.xml`. The null driver
reports *skipped*, never clean.

## A fake engine

```php
final class FakeMalwareScanner implements MalwareScanner
{
    public static function clean(): self;
    public static function infected(string $signature = 'Test.Fake'): self;
    public static function unavailable(): self;   // throws ScannerUnavailableException
    public static function timingOut(): self;     // throws ScanTimeoutException
}
```

It fakes the *verdict*, never the detection. There are no signatures in it.

## Test that you fail closed

The single most important test of your integration:

```php
it('rejects uploads when the scanner is down', function (): void {
    ContentSecurity::extend('clamav', fn () => FakeMalwareScanner::unavailable());
    config()->set('content-security.malware.default', 'clamav');

    $this->post('/applications', [
        'cv' => UploadedFile::fake()->create('cv.pdf', 100),
    ])->assertSessionHasErrors('cv');
});
```

If this passes with a green tick and your endpoint still accepted the file,
your integration is not fail-closed regardless of what the config says.

## EICAR

For an end-to-end test against a real daemon:

```php
$eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
```

68 printable ASCII characters that every engine is required to flag and which
do nothing if executed. Keep these in a separate suite that only runs where
`clamd` exists.

## Fake the disks

```php
Storage::fake('quarantine');

$this->post('/upload', ['file' => UploadedFile::fake()->create('shell.php', 1)]);

expect(Storage::disk('quarantine')->allFiles())->toHaveCount(1);
```

## Events

```php
Event::fake([ThreatDetected::class]);

// ContentSecurity and its actions are singletons holding the pre-fake
// dispatcher — drop them so the next call rebuilds against the fake.
app()->forgetInstance(ContentSecurity::class);
app()->forgetInstance(ScanFile::class);
ContentSecurity::clearResolvedInstances();
```

## Gotchas

**Watch your fixture filenames.** `uniqid(more_entropy: true)` contains a dot,
which trips the double-extension check and makes every fixture look suspicious
for reasons unrelated to your test.

**Minimal PDFs need `%%EOF`.** `'%PDF-1.4 test'` is correctly flagged as
truncated. Use:

```php
"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF"
```

**Config read at boot stays read.** Route middleware is bound when the provider
boots, so changing `content-security.admin.middleware` in a `beforeEach` has no
effect. Set it in your test case's environment setup.
