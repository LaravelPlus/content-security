<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Policy;

enum FailureAction: string
{
    /** Refuse the upload and leave nothing behind. */
    case Reject = 'reject';

    /** Refuse the upload but keep the evidence in the quarantine disk. */
    case Quarantine = 'quarantine';

    public function label(): string
    {
        return ucfirst($this->value);
    }
}
