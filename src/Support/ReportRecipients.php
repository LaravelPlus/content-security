<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Support;

/** `content-security.reports.recipients`: a comma-separated string or an array. */
final class ReportRecipients
{
    /** @return list<string> */
    public static function configured(): array
    {
        /** @var list<string>|string|null $configured */
        $configured = config('content-security.reports.recipients');

        if (is_string($configured)) {
            $configured = array_map(trim(...), explode(',', $configured));
        }

        return array_values(array_filter((array) $configured));
    }
}
