<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Scan;

enum ScanType: string
{
    case File = 'file';
    case Text = 'text';
    case Html = 'html';
    case Url = 'url';

    public function label(): string
    {
        return match ($this) {
            self::File => 'File',
            self::Text => 'Text',
            self::Html => 'HTML',
            self::Url => 'URL',
        };
    }
}
