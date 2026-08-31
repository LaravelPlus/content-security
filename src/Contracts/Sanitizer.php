<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

interface Sanitizer
{
    /**
     * Returns HTML safe to render. Never a boolean — sanitizing is a
     * transformation, and callers that only want a verdict compare the
     * output with the input.
     */
    public function sanitize(string $html): string;
}
