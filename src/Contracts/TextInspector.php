<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Contracts;

use LaravelPlus\ContentSecurity\Domain\Scan\Findings;

interface TextInspector extends Inspector
{
    public function inspect(string $text): Findings;
}
