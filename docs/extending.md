# Extending

Everything here is designed so you never have to fork the package.

## A custom malware engine

```php
use LaravelPlus\ContentSecurity\Contracts\MalwareScanner;

final class YaraScanner implements MalwareScanner
{
    public function name(): string { return 'yara'; }

    public function scan(FileReference $file): CheckResult
    {
        // MUST throw ScannerUnavailableException or ScanTimeoutException
        // when it cannot scan. Never return a pass.
    }

    public function health(): ScannerHealth { /* … */ }
}
```

```php
ContentSecurity::extend('yara', fn ($app, array $config) => new YaraScanner($config));
```

```php
'malware' => [
    'default' => 'yara',
    'drivers' => ['yara' => ['driver' => 'yara', 'rules' => '/etc/yara/rules']],
],
```

The one hard requirement: **an engine that cannot answer must throw.**
Returning clean when you did not scan defeats the entire package.

## A custom check

Extend the abstract base. Report findings; do not score them — severity lives
in one place so every check answers "how bad is this?" the same way.

```php
use LaravelPlus\ContentSecurity\File\Checks\AbstractFileCheck;

final class WatermarkCheck extends AbstractFileCheck
{
    public function __construct(private readonly WatermarkReader $reader) {}

    public function key(): string { return 'watermark'; }

    public function label(): string { return 'Watermark'; }

    public function appliesTo(FileReference $file, FilePolicy $policy): bool
    {
        return $file->extension() === 'pdf';
    }

    protected function inspect(FileReference $file, FilePolicy $policy, ScanContext $context): Findings
    {
        if ($this->reader->isMissing($file->path)) {
            return Findings::of(Threat::make(
                name: 'document.unwatermarked',
                level: ThreatLevel::Medium,
                source: $this->key(),
                description: 'The document carries no corporate watermark.',
            ), ['checked' => true]);
        }

        return Findings::none(['checked' => true]);
    }
}
```

```php
ContentSecurity::addFileCheck(WatermarkCheck::class, before: MalwareCheck::class);
ContentSecurity::addTextCheck(ProfanityCheck::class);
ContentSecurity::removeCheck(PdfCheck::class);   // prefer disabling in the policy
```

Checks are held as class names and resolved from the container per scan, so
constructor injection works and nothing is instantiated at registration time.

Throwing from `inspect()` is fine — the base class turns it into a failed
check. Returning a pass when you could not actually check is not.

Add the key to your policies so it can be switched per slot:

```php
'checks' => [/* … */, 'watermark' => true],
```

## Hooks

```php
// Before any check. Amend the context and return it.
ContentSecurity::beforeScan(fn (ScanContext $c) => $c->withActor(auth()->id(), request()->header('X-Request-Id')));

// After the pipeline, before persistence and events. The returned result is
// what everything downstream sees.
ContentSecurity::afterScan(function (ScanResult $result, ScanContext $context): ScanResult {
    return $result;
});
```

`afterScan` can downgrade a finding your application knows to be a false
positive — deliberately, and in one auditable place rather than scattered
through controllers.

## Policies from your own store

```php
ContentSecurity::resolveFilePolicyUsing(
    fn (string $name): FilePolicy => Tenant::current()->policy($name),
);
```

Or bind the whole repository:

```php
$this->app->singleton(PolicyRepository::class, MyTenantPolicyRepository::class);
```

## Replacing a collaborator

Every one is bound to a contract:

| Contract | Default |
| --- | --- |
| `MalwareScanner` | `ClamAvScanner` / `NullMalwareScanner` (`none`) |
| `Sanitizer` | `HtmlSanitizer` (symfony/html-sanitizer) |
| `ArchiveInspector` | `ArchiveInspector` |
| `ImageInspector` | `ImageInspector` |
| `PdfInspector` | `PdfInspector` |
| `TextInspector` | `SuspiciousContentScanner` |
| `UrlInspector` | `UrlScanner` |
| `ScanRepository` | `EloquentScanRepository` / `NullScanRepository` |
| `PolicyRepository` | `DatabasePolicyRepository` / `ConfigPolicyRepository` |

```php
$this->app->singleton(PdfInspector::class, MyPdfInspector::class);
```

## Storing scans elsewhere

Implement `ScanRepository` and bind it. The pipeline never talks to Eloquent
directly.

```php
$this->app->singleton(ScanRepository::class, OpenSearchScanRepository::class);
```
