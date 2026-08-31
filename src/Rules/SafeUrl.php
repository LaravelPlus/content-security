<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use LaravelPlus\ContentSecurity\Contracts\UrlInspector;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 *   'website' => ['nullable', new SafeUrl()],
 *
 * Structural checks always; SSRF checks when `urls.ssrf_protection` is on.
 *
 * A URL that passes here is safe to *store and display*. It is not thereby
 * safe to *fetch* — see docs/url-security.md on DNS rebinding and on
 * pinning the address you validated.
 */
final class SafeUrl implements ValidationRule
{
    private ?Findings $findings = null;

    public function __construct(private readonly UrlInspector $inspector) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! (bool) config('content-security.enabled', true) || ! is_string($value) || $value === '') {
            return;
        }

        $this->findings = $this->inspector->inspect($value);

        if (! $this->findings->hasAtLeast(ThreatLevel::Medium)) {
            return;
        }

        // URLs are the one place a specific message is safe and genuinely
        // useful: the user pasted it, they can see it, and naming the scheme
        // reveals nothing they did not already type.
        $first = $this->findings->threats[0];

        $fail(match ($first->name) {
            'url.scheme_not_allowed' => (string) __('content-security::validation.url_scheme'),
            'url.embedded_credentials' => (string) __('content-security::validation.url_credentials'),
            'url.internal_destination' => (string) __('content-security::validation.url_internal'),
            'url.suspicious_unicode_host' => (string) __('content-security::validation.url_unicode'),
            default => (string) __('content-security::validation.url_invalid'),
        });
    }

    public function findings(): ?Findings
    {
        return $this->findings;
    }
}
