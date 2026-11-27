<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Policy;

/** What a finding does to the upload, set per code in `findings`. */
enum FindingAction: string
{
    /** Recorded and reported, but does not decide the verdict. */
    case Allow = 'allow';

    /** Blocks the upload and discards it, whatever the policy's on_threat says. */
    case Reject = 'reject';

    /** Blocks the upload and keeps it in quarantine, whatever on_threat says. */
    case Quarantine = 'quarantine';
}
