<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;
use Illuminate\Translation\PotentiallyTranslatedString;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Rules\Concerns\ReportsScanFailures;
use LaravelPlus\ContentSecurity\Support\Bytes;
use LaravelPlus\ContentSecurity\Support\HookRegistry;

/**
 * The full pipeline, as a validation rule.
 *
 *   'attachment'  => ['required', 'file', new SafeFile()],
 *   'avatar'      => ['required', 'image', (new SafeFile('images'))->maxSize('2 MB')],
 *   'attachments' => ['required', 'array', new SafeFile('support')],
 *
 * The server names the policy; nothing in the request can choose it. On an
 * array of uploads the policy's `max_files` and `max_total_size` apply to
 * the batch, then every file is scanned. The per-field limits below can
 * only tighten the policy, never widen it, and size limits are checked from
 * the upload's size before any file is read.
 *
 * The last scan result is available via `result()` afterwards, so a
 * controller can record the scan id against its own model.
 */
final class SafeFile implements ValidationRule
{
    use ReportsScanFailures;

    private ?ScanResult $result = null;

    private ?int $maxSize = null;

    private ?int $maxFiles = null;

    private ?int $maxTotalSize = null;

    public function __construct(private readonly FilePolicy|string|null $policy = null) {}

    /** Per-field size limit, bytes or "10 MB". Only ever stricter than the policy. */
    public function maxSize(int|string $size): self
    {
        $this->maxSize = Bytes::parse($size);

        return $this;
    }

    /** Per-field file count for an array of uploads. Only ever stricter than the policy. */
    public function maxFiles(int $count): self
    {
        $this->maxFiles = max(1, $count);

        return $this;
    }

    /** Per-field batch size, bytes or "50 MB". Only ever stricter than the policy. */
    public function maxTotalSize(int|string $size): self
    {
        $this->maxTotalSize = Bytes::parse($size);

        return $this;
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! (bool) config('content-security.enabled', true)) {
            return;
        }

        if (is_array($value)) {
            $this->validateBatch($attribute, $value, $fail);

            return;
        }

        if (! $value instanceof UploadedFile) {
            // Not a file. Leave that verdict to Laravel's own `file` rule
            // rather than producing a second, confusing message for it.
            return;
        }

        if (! $value->isValid()) {
            $fail(__('content-security::validation.upload_failed'))->translate();

            return;
        }

        if ($this->maxSize !== null && (int) $value->getSize() > $this->maxSize) {
            $fail(__('content-security::validation.too_large', ['max' => Bytes::humanize($this->maxSize)]))->translate();

            return;
        }

        $this->result = ContentSecurity::scanFile($value, $this->policy);

        if (! $this->result->isClean()) {
            $fail($this->messageFor($this->result));
        }
    }

    /**
     * @param  array<array-key, mixed>  $files
     */
    private function validateBatch(string $attribute, array $files, Closure $fail): void
    {
        $policy = $this->resolvePolicy();
        $maxFiles = $this->stricter($policy->maxFiles, $this->maxFiles);
        $maxTotal = $this->stricter($policy->maxTotalSize, $this->maxTotalSize);

        if ($maxFiles !== null && count($files) > $maxFiles) {
            $fail(__('content-security::validation.too_many_files', ['max' => $maxFiles]))->translate();

            return;
        }

        $total = array_sum(array_map(
            static fn (mixed $file): int => $file instanceof UploadedFile ? (int) $file->getSize() : 0,
            $files,
        ));

        if ($maxTotal !== null && $total > $maxTotal) {
            $fail(__('content-security::validation.batch_too_large', ['max' => Bytes::humanize($maxTotal)]))->translate();

            return;
        }

        foreach ($files as $key => $file) {
            $failed = false;
            $this->validate($attribute.'.'.$key, $file, function (string $message) use ($fail, &$failed): PotentiallyTranslatedString {
                $failed = true;

                return $fail($message);
            });

            if ($failed) {
                return;
            }
        }
    }

    private function resolvePolicy(): FilePolicy
    {
        return $this->policy instanceof FilePolicy
            ? $this->policy
            : app(HookRegistry::class)->filePolicy($this->policy ?? (string) config('content-security.files.default_policy', 'default'));
    }

    private function stricter(?int $policy, ?int $field): ?int
    {
        return $policy === null || $field === null ? ($policy ?? $field) : min($policy, $field);
    }

    public function result(): ?ScanResult
    {
        return $this->result;
    }
}
