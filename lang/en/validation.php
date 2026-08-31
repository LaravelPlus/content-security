<?php

declare(strict_types=1);

return [
    // Deliberately non-specific: see Rules\Concerns\ReportsScanFailures.
    'rejected' => 'This :subject did not pass a security check.',
    'scan_failed' => 'This :subject could not be security checked. Please try again.',
    'upload_failed' => 'The upload did not complete. Please try again.',
    'malware_detected' => 'This file did not pass a security check.',

    'url_invalid' => 'This does not look like a valid web address.',
    'url_scheme' => 'Only http:// and https:// addresses are accepted.',
    'url_credentials' => 'Web addresses containing a username or password are not accepted.',
    'url_internal' => 'This address points to an internal destination and cannot be used.',
    'url_unicode' => 'This web address uses characters that can imitate another domain.',
];
