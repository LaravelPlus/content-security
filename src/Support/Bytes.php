<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Support;

final class Bytes
{
    public static function humanize(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $value = (float) $bytes;
        $unit = 0;

        while ($value >= 1024 && $unit < count($units) - 1) {
            $value /= 1024;
            $unit++;
        }

        return $unit === 0
            ? sprintf('%d %s', (int) $value, $units[$unit])
            : sprintf('%.1f %s', $value, $units[$unit]);
    }
}
