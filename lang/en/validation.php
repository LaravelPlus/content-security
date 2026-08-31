<?php

declare(strict_types=1);

return [
    // Deliberately non-specific about WHY: see Rules\Concerns\ReportsScanFailures.
    // One key per subject rather than a :subject placeholder — interpolating an
    // English noun into a translated sentence produced "Ta file ni prestal ...".
    'rejected_file' => 'This file did not pass a security check.',
    'rejected_text' => 'This text did not pass a security check.',
    'rejected_content' => 'This content did not pass a security check.',

    'failed_file' => 'This file could not be security checked. Please try again.',
    'failed_text' => 'This text could not be security checked. Please try again.',
    'failed_content' => 'This content could not be security checked. Please try again.',

    'upload_failed' => 'The upload did not complete. Please try again.',
    'malware_detected' => 'This file did not pass a security check.',

    'url_invalid' => 'This does not look like a valid web address.',
    'url_scheme' => 'Only http:// and https:// addresses are accepted.',
    'url_credentials' => 'Web addresses containing a username or password are not accepted.',
    'url_internal' => 'This address points to an internal destination and cannot be used.',
    'url_unicode' => 'This web address uses characters that can imitate another domain.',
];
