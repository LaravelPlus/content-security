<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

/**
 * Marker for the collaborators that examine one kind of content and report
 * findings. Kept separate from SecurityCheck: an inspector knows a format,
 * a check knows the pipeline and the policy. That split is what lets a host
 * swap the PDF inspector without touching how PDFs are scheduled or scored.
 */
interface Inspector {}
