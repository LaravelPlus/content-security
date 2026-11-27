<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Support;

use InvalidArgumentException;

final class Bytes
{
    private const array UNITS = ['b' => 0, 'kb' => 1, 'kib' => 1, 'mb' => 2, 'mib' => 2, 'gb' => 3, 'gib' => 3, 'tb' => 4, 'tib' => 4];

    /**
     * An integer byte count, or a human size such as `500 KB`, `10 MB`,
     * `2 GB`. Units are binary: KB and KiB both mean 1024 bytes, matching
     * humanize() and the `* 1024 * 1024` values already in the config.
     *
     * @throws InvalidArgumentException for anything else, or a size below 1 byte
     */
    public static function parse(mixed $value): int
    {
        if (is_string($value) && preg_match('/^\s*(\d+(?:\.\d+)?)\s*([a-z]*)\s*$/i', $value, $m) === 1
            && ($m[2] === '' || array_key_exists(strtolower($m[2]), self::UNITS))) {
            $value = (int) round((float) $m[1] * 1024 ** self::UNITS[strtolower($m[2] ?: 'b')]);
        }

        if (! is_int($value) || $value < 1) {
            throw new InvalidArgumentException(sprintf('Invalid size [%s]: use bytes or a size like "10 MB".', is_scalar($value) ? (string) $value : get_debug_type($value)));
        }

        return $value;
    }

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
