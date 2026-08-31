<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Rules\Concerns;

use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;

/**
 * The one place that decides what an end user is told when a scan rejects
 * their input.
 *
 * The rule: enough to be actionable, never enough to be a probe. "This file
 * did not pass a security check" is useful. "Detected Win.Trojan.X by ClamAV"
 * tells an attacker which of their attempts got closest, and turns a
 * validation endpoint into a free malware sandbox.
 *
 * The full result stays in the audit log and the admin console, where the
 * people entitled to it can read it.
 */
trait ReportsScanFailures
{
    protected function messageFor(ScanResult $result, string $subject = 'file'): string
    {
        return $result->failed()
            ? (string) __('content-security::validation.scan_failed', ['subject' => $subject])
            : (string) __('content-security::validation.rejected', ['subject' => $subject]);
    }
}
