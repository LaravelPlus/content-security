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
 *   'bio' => ['required', 'string', new SafeText()],
 *
 * Heuristic by nature — read the note on SuspiciousContentScanner. This is
 * a tripwire on a field that should never contain markup or SQL, not a
 * substitute for parameterised queries or output escaping.
 */
final class SafeText implements ValidationRule
{
    use ReportsScanFailures;

    private ?ScanResult $result = null;

    public function __construct(private readonly TextPolicy|string|null $policy = null) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! (bool) config('content-security.enabled', true) || ! is_string($value)) {
            return;
        }

        $this->result = ContentSecurity::scanText($value, $this->policy);

        if (! $this->result->isClean()) {
            $fail($this->messageFor($this->result, 'text'));
        }
    }

    public function result(): ?ScanResult
    {
        return $this->result;
    }
}
