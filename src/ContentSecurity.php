<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity;

use Closure;
use Illuminate\Contracts\Bus\Dispatcher as BusDispatcher;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Gate;
use LaravelPlus\ContentSecurity\Actions\QuarantineFile;
use LaravelPlus\ContentSecurity\Actions\ScanFile;
use LaravelPlus\ContentSecurity\Actions\ScanText;
use LaravelPlus\ContentSecurity\Contracts\FileCheck;
use LaravelPlus\ContentSecurity\Contracts\FileScanner;
use LaravelPlus\ContentSecurity\Contracts\MalwareScanner;
use LaravelPlus\ContentSecurity\Contracts\Sanitizer;
use LaravelPlus\ContentSecurity\Contracts\SecurityCheck;
use LaravelPlus\ContentSecurity\Contracts\TextCheck;
use LaravelPlus\ContentSecurity\Contracts\TextScanner;
use LaravelPlus\ContentSecurity\Contracts\UrlInspector;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanType;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use LaravelPlus\ContentSecurity\Exceptions\PolicyViolationException;
use LaravelPlus\ContentSecurity\File\Malware\MalwareScannerManager;
use LaravelPlus\ContentSecurity\Jobs\ScanFileJob;
use LaravelPlus\ContentSecurity\Pipeline\CheckRegistry;
use LaravelPlus\ContentSecurity\Support\HookRegistry;
use LaravelPlus\ContentSecurity\Support\ScannerHealth;

/**
 * The package's front door, and the object behind the ContentSecurity facade.
 *
 * Everything an application needs is here: scan, sanitize, queue, extend,
 * authorize. The implementations sit behind contracts, so this class is a
 * façade in the design sense too — it composes, it does not do the work.
 *
 * Note that scanning is a *layer*. It does not replace parameterised
 * queries, output escaping, authorization or a Content-Security-Policy
 * header; see the security notes in the README.
 */
final class ContentSecurity implements FileScanner, TextScanner
{
    public function __construct(
        private readonly ScanFile $scanFile,
        private readonly QuarantineFile $quarantine,
        private readonly ScanText $scanText,
        private readonly MalwareScannerManager $scanners,
        private readonly Sanitizer $sanitizer,
        private readonly UrlInspector $urls,
        private readonly CheckRegistry $checks,
        private readonly HookRegistry $hooks,
        private readonly BusDispatcher $bus,
    ) {}

    // ---------------------------------------------------------------------
    // Scanning
    // ---------------------------------------------------------------------

    /**
     * @param  UploadedFile|FileReference|string  $file  an upload, a reference, or an absolute path
     */
    public function scanFile(UploadedFile|FileReference|string $file, FilePolicy|string|null $policy = null): ScanResult
    {
        $reference = $this->reference($file);

        try {
            return $this->scanFile->handle($reference, $this->policyName($policy));
        } finally {
            $reference->discardTemporary();
        }
    }

    /** Scans a file that already lives on a Flysystem disk. */
    public function scanDisk(string $disk, string $path, FilePolicy|string|null $policy = null): ScanResult
    {
        $reference = FileReference::fromDisk($disk, $path);

        try {
            return $this->scanFile->handle($reference, $this->policyName($policy));
        } finally {
            $reference->discardTemporary();
        }
    }

    /**
     * @throws PolicyViolationException when the file is not clean
     */
    public function scanFileOrFail(UploadedFile|FileReference|string $file, FilePolicy|string|null $policy = null): ScanResult
    {
        $result = $this->scanFile($file, $policy);

        if (! $result->isClean()) {
            throw PolicyViolationException::from($result);
        }

        return $result;
    }

    public function scanText(string $text, TextPolicy|string|null $policy = null): ScanResult
    {
        return $this->scanText->handle($text, $this->textPolicyName($policy));
    }

    /**
     * Scans text as rich HTML: the sanitizer runs, and what it removed
     * becomes the finding.
     */
    public function scanHtml(string $html, TextPolicy|string|null $policy = null): ScanResult
    {
        return $this->scanText->handle(
            $html,
            $this->textPolicyName($policy) ?? 'rich',
            ScanType::Html,
        );
    }

    /**
     * @throws PolicyViolationException when the text is not clean
     */
    public function scanTextOrFail(string $text, TextPolicy|string|null $policy = null): ScanResult
    {
        $result = $this->scanText($text, $policy);

        if (! $result->isClean()) {
            throw PolicyViolationException::from($result);
        }

        return $result;
    }

    /** Returns HTML safe to render, with everything unlisted removed. */
    public function sanitizeHtml(string $html): string
    {
        return $this->sanitizer->sanitize($html);
    }

    public function scanUrl(string $url): ScanResult
    {
        $context = ScanContext::for(ScanType::Url, 'default');
        $findings = $this->urls->inspect($url);

        return new ScanResult(
            scanId: $context->scanId,
            type: ScanType::Url,
            status: $this->urlStatus($findings),
            threats: $findings->threats,
            scanner: 'url',
            metadata: $findings->metadata,
        );
    }

    public function isSafeUrl(string $url): bool
    {
        return $this->urls->isSafe($url);
    }

    // ---------------------------------------------------------------------
    // Queued scanning
    // ---------------------------------------------------------------------

    /**
     * Copies the file into quarantine storage and scans it on a worker.
     *
     * The file goes to the quarantine disk *first*, before any verdict —
     * that is the point of the design. An unscanned upload must never sit in
     * the application's normal storage waiting to be judged.
     *
     * Returns the scan id to poll or to store against your own record.
     */
    public function queue(UploadedFile|FileReference|string $file, FilePolicy|string|null $policy = null): ScanId
    {
        $reference = $this->reference($file);
        $scanId = ScanId::generate();

        try {
            $path = $this->quarantine->handle($reference, $scanId);
        } finally {
            $reference->discardTemporary();
        }

        $this->bus->dispatch(new ScanFileJob(
            scanId: $scanId,
            disk: (string) config('content-security.storage.quarantine_disk', 'local'),
            path: $path,
            originalName: $reference->originalName,
            policy: $this->policyName($policy),
        ));

        return $scanId;
    }

    // ---------------------------------------------------------------------
    // Engines and health
    // ---------------------------------------------------------------------

    public function scanner(?string $name = null): MalwareScanner
    {
        return $this->scanners->driver($name);
    }

    /**
     * @return list<ScannerHealth>
     */
    public function health(): array
    {
        $active = $this->scanners->defaultDriver();
        $health = [];

        foreach ($this->scanners->configuredDrivers() as $driver) {
            $health[] = $this->scanners->driver($driver)
                ->health()
                ->asActive($driver === $active);
        }

        return $health;
    }

    // ---------------------------------------------------------------------
    // Extension points
    // ---------------------------------------------------------------------

    /**
     * Registers a malware engine of your own.
     *
     *   ContentSecurity::extend('yara', fn ($app, $config) => new YaraScanner(...));
     *
     * @param  Closure(Container, array<string, mixed>): MalwareScanner  $factory
     */
    public function extend(string $driver, Closure $factory): self
    {
        $this->scanners->extend($driver, $factory);

        return $this;
    }

    /**
     * Adds a file check. Extend AbstractFileCheck and pass the class name;
     * it is resolved from the container, so constructor injection works.
     *
     * @param  class-string<FileCheck>  $check
     * @param  class-string<FileCheck>|null  $before
     * @param  class-string<FileCheck>|null  $after
     */
    public function addFileCheck(string $check, ?string $before = null, ?string $after = null): self
    {
        $this->checks->addFileCheck($check, $before, $after);

        return $this;
    }

    /**
     * @param  class-string<TextCheck>  $check
     * @param  class-string<TextCheck>|null  $before
     * @param  class-string<TextCheck>|null  $after
     */
    public function addTextCheck(string $check, ?string $before = null, ?string $after = null): self
    {
        $this->checks->addTextCheck($check, $before, $after);

        return $this;
    }

    /**
     * @param  class-string<SecurityCheck>  $check
     */
    public function removeCheck(string $check): self
    {
        $this->checks->remove($check);

        return $this;
    }

    /**
     * Runs before every scan. Amend the context — tenant, request id, actor
     * — and return it.
     *
     * @param  Closure(ScanContext): ScanContext  $callback
     */
    public function beforeScan(Closure $callback): self
    {
        $this->hooks->before($callback);

        return $this;
    }

    /**
     * Runs after the pipeline and before persistence. The returned result is
     * authoritative.
     *
     * @param  Closure(ScanResult, ScanContext): ScanResult  $callback
     */
    public function afterScan(Closure $callback): self
    {
        $this->hooks->after($callback);

        return $this;
    }

    /**
     * Resolve policies from somewhere other than the config file — a table,
     * a per-tenant setting.
     *
     * @param  Closure(string): FilePolicy  $resolver
     */
    public function resolveFilePolicyUsing(Closure $resolver): self
    {
        $this->hooks->resolveFilePolicyUsing($resolver);

        return $this;
    }

    /**
     * @param  Closure(string): TextPolicy  $resolver
     */
    public function resolveTextPolicyUsing(Closure $resolver): self
    {
        $this->hooks->resolveTextPolicyUsing($resolver);

        return $this;
    }

    /**
     * Who may open the admin console. The package has no opinion about your
     * authorization model and will not guess one.
     *
     *   ContentSecurity::auth(fn (User $user) => $user->isAdmin());
     *
     * @param  Closure(mixed): bool  $callback
     */
    public function auth(Closure $callback): self
    {
        $this->hooks->authorizeUsing($callback);

        return $this;
    }

    public function authorize(mixed $user): bool
    {
        if ($this->hooks->hasAuthorization()) {
            return $this->hooks->authorize($user);
        }

        /** @var string|null $gate */
        $gate = config('content-security.admin.gate');

        if (is_string($gate) && $gate !== '') {
            return Gate::forUser($user)->allows($gate);
        }

        // No callback, no gate: deny. An admin console that defaults open
        // because nobody configured it is how this package would become the
        // vulnerability it exists to prevent.
        return false;
    }

    public function hooks(): HookRegistry
    {
        return $this->hooks;
    }

    public function checks(): CheckRegistry
    {
        return $this->checks;
    }

    // ---------------------------------------------------------------------

    private function reference(UploadedFile|FileReference|string $file): FileReference
    {
        return match (true) {
            $file instanceof FileReference => $file,
            $file instanceof UploadedFile => FileReference::fromUploadedFile($file),
            default => FileReference::fromPath($file),
        };
    }

    private function policyName(FilePolicy|string|null $policy): ?string
    {
        return $policy instanceof FilePolicy ? $policy->name() : $policy;
    }

    private function textPolicyName(TextPolicy|string|null $policy): ?string
    {
        return $policy instanceof TextPolicy ? $policy->name() : $policy;
    }

    private function urlStatus(Findings $findings): ScanStatus
    {
        return match (true) {
            $findings->isEmpty() => ScanStatus::Clean,
            $findings->hasAtLeast(ThreatLevel::High) => ScanStatus::Infected,
            default => ScanStatus::Suspicious,
        };
    }
}
