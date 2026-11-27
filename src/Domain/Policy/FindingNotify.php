<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Policy;

/** Who hears about a finding, set per code in `findings`. */
enum FindingNotify: string
{
    /** Recorded in the audit trail only; left out of the mail digest. */
    case None = 'none';

    /** Reported in the daily/weekly digest (the default). */
    case Digest = 'digest';

    /** Also mailed to the report recipients as soon as the scan completes. */
    case Immediate = 'immediate';
}
