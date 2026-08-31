<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Tests\Integration;

use Illuminate\Process\Factory;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\File\Malware\ClamAv\ClamAvConfig;
use LaravelPlus\ContentSecurity\File\Malware\ClamAv\ClamAvResultParser;
use LaravelPlus\ContentSecurity\File\Malware\ClamAv\ClamAvScanner;
use LaravelPlus\ContentSecurity\File\Malware\ClamAv\ClamAvSocketClient;
use LaravelPlus\ContentSecurity\Tests\TestCase;

/**
 * Runs only where a real clamd is reachable — its own suite so
 * `composer test` passes on a laptop with no antivirus installed.
 *
 *     vendor/bin/pest --testsuite=Integration
 */
final class ClamAvTest extends TestCase
{
    /**
     * EICAR: the industry's standard harmless test file. 68 printable ASCII
     * characters that every engine is required to flag, and which do nothing
     * whatsoever if executed. Split here so this source file does not itself
     * trip a scanner watching the repository.
     */
    private const EICAR_PREFIX = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-';

    private const EICAR_SUFFIX = 'ANTIVIRUS-TEST-FILE!$H+H*';

    private function scanner(): ClamAvScanner
    {
        $config = ClamAvConfig::fromArray([
            'connection' => env('CONTENT_SECURITY_CLAMAV_CONNECTION', 'tcp'),
            'host' => env('CONTENT_SECURITY_CLAMAV_HOST', '127.0.0.1'),
            'port' => (int) env('CONTENT_SECURITY_CLAMAV_PORT', 3310),
            'unix_socket' => env('CONTENT_SECURITY_CLAMAV_SOCKET', '/var/run/clamav/clamd.ctl'),
            'timeout' => 60,
        ]);

        return new ClamAvScanner(
            $config,
            new ClamAvSocketClient($config),
            new ClamAvResultParser,
            $this->app->make(Factory::class),
        );
    }

    private function file(string $name, string $contents): FileReference
    {
        $directory = sys_get_temp_dir().'/cs-integration-'.bin2hex(random_bytes(6));
        mkdir($directory);
        $path = $directory.'/'.$name;
        file_put_contents($path, $contents);

        return FileReference::fromPath($path);
    }

    public function test_the_daemon_is_reachable(): void
    {
        $health = $this->scanner()->health();

        $this->assertTrue($health->online, $health->error ?? 'clamd did not respond');
        $this->assertNotNull($health->version);
        $this->assertNotNull($health->signatureVersion);
    }

    public function test_a_clean_file_passes(): void
    {
        $result = $this->scanner()->scan($this->file('notes.txt', 'perfectly ordinary content'));

        $this->assertSame(ScanStatus::Clean, $result->status);
        $this->assertSame([], $result->threats);
    }

    public function test_the_eicar_test_file_is_detected(): void
    {
        $result = $this->scanner()->scan(
            $this->file('eicar.com', self::EICAR_PREFIX.self::EICAR_SUFFIX),
        );

        $this->assertSame(ScanStatus::Infected, $result->status);
        $this->assertNotEmpty($result->threats);
        $this->assertStringContainsStringIgnoringCase('eicar', $result->threats[0]->name);
    }

    public function test_a_large_file_streams_rather_than_buffering(): void
    {
        $before = memory_get_peak_usage(true);

        $result = $this->scanner()->scan(
            $this->file('big.bin', str_repeat('a', 32 * 1024 * 1024)),
        );

        $growth = memory_get_peak_usage(true) - $before;

        $this->assertSame(ScanStatus::Clean, $result->status);
        // The file is 32 MB; INSTREAM sends it in 64 KB chunks, so PHP's peak
        // must not grow by anything like the file size.
        $this->assertLessThan(16 * 1024 * 1024, $growth);
    }
}
