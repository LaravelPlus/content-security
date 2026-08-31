<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Rules\Concerns\ReportsScanFailures;

/**
 *   'description' => ['required', new SafeHtml()],
 *
 * Rejects rich text that carries markup the sanitizer would have to strip.
 *
 * There is a gentler option, and for user-facing forms it is usually the
 * better one: accept the input and store `ContentSecurity::sanitizeHtml()`
 * instead. Rejecting tells someone pasting from Word that their input is
 * "unsafe"; sanitizing just quietly removes the `<o:p>` tags. Reach for the
 * rule when unexpected markup is itself the signal you want to act on.
 */
final class SafeHtml implements ValidationRule
{
    use ReportsScanFailures;

    private ?ScanResult $result = null;

    public function __construct(private readonly TextPolicy|string|null $policy = null) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! (bool) config('content-security.enabled', true) || ! is_string($value)) {
            return;
        }

        $this->result = ContentSecurity::scanHtml($value, $this->policy);

        if (! $this->result->isClean()) {
            $fail($this->messageFor($this->result, 'content'));
        }
    }

    /** The cleaned markup, for a caller that wants to store it. */
    public function sanitized(): ?string
    {
        foreach ($this->result?->checks() ?? [] as $check) {
            $sanitized = $check->metadata['sanitized'] ?? null;

            if ($check->check === 'html' && is_string($sanitized)) {
                return $sanitized;
            }
        }

        return null;
    }

    public function result(): ?ScanResult
    {
        return $this->result;
    }
}
