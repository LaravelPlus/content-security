<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Rules\Concerns\ReportsScanFailures;

/**
 * The full pipeline, as a validation rule.
 *
 *   'attachment' => ['required', 'file', new SafeFile()],
 *   'avatar'     => ['required', 'image', new SafeFile('images')],
 *
 * The last scan result is available via `result()` afterwards, so a
 * controller can record the scan id against its own model.
 */
final class SafeFile implements ValidationRule
{
    use ReportsScanFailures;

    private ?ScanResult $result = null;

    public function __construct(private readonly FilePolicy|string|null $policy = null) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! (bool) config('content-security.enabled', true)) {
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

        $this->result = ContentSecurity::scanFile($value, $this->policy);

        if (! $this->result->isClean()) {
            $fail($this->messageFor($this->result));
        }
    }

    public function result(): ?ScanResult
    {
        return $this->result;
    }
}
