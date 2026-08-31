<?php

declare(strict_types=1);

use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;

function makeZip(callable $build): string
{
    $directory = sys_get_temp_dir().'/cs-zip-'.bin2hex(random_bytes(6));
    mkdir($directory);
    $path = $directory.'/archive.zip';

    $zip = new ZipArchive;
    $zip->open($path, ZipArchive::CREATE);
    $build($zip);
    $zip->close();

    return $path;
}

function threatNames(ScanResult $result): array
{
    return array_map(static fn ($threat) => $threat->name, $result->threats());
}

beforeEach(function (): void {
    config()->set('content-security.malware.default', 'null');
});

it('passes an ordinary archive', function (): void {
    $path = makeZip(static function (ZipArchive $zip): void {
        $zip->addFromString('readme.txt', 'hello');
        $zip->addFromString('data/notes.txt', 'more');
    });

    expect(ContentSecurity::scanFile($path)->isClean())->toBeTrue();
});

it('detects a compression bomb', function (): void {
    // Highly compressible: ~10 MB of zeros in a few KB of zip.
    $path = makeZip(static function (ZipArchive $zip): void {
        $zip->addFromString('bomb.bin', str_repeat("\0", 10 * 1024 * 1024));
    });

    config()->set('content-security.archives.max_compression_ratio', 50);

    $result = ContentSecurity::scanFile($path);

    expect($result->isClean())->toBeFalse()
        ->and(threatNames($result))->toContain('archive.compression_bomb');
});

it('detects path traversal entries', function (): void {
    $path = makeZip(static function (ZipArchive $zip): void {
        $zip->addFromString('../../etc/cron.d/backdoor', 'evil');
    });

    $result = ContentSecurity::scanFile($path);

    expect(threatNames($result))->toContain('archive.path_traversal');
});

it('detects executable entries', function (): void {
    $path = makeZip(static function (ZipArchive $zip): void {
        $zip->addFromString('docs/readme.txt', 'hello');
        $zip->addFromString('setup.exe', 'MZ binary');
    });

    $result = ContentSecurity::scanFile($path);

    expect(threatNames($result))->toContain('archive.executable_entry');
});

it('enforces the file-count limit', function (): void {
    config()->set('content-security.archives.max_files', 5);

    $path = makeZip(static function (ZipArchive $zip): void {
        for ($i = 0; $i < 40; $i++) {
            $zip->addFromString("file-{$i}.txt", 'x');
        }
    });

    $result = ContentSecurity::scanFile($path);

    expect(threatNames($result))->toContain('archive.too_many_files');
});

it('reports each breached limit once, not once per entry', function (): void {
    config()->set('content-security.archives.max_files', 2);

    $path = makeZip(static function (ZipArchive $zip): void {
        for ($i = 0; $i < 200; $i++) {
            $zip->addFromString("file-{$i}.txt", 'x');
        }
    });

    $names = threatNames(ContentSecurity::scanFile($path));

    expect(array_count_values($names)['archive.too_many_files'])->toBe(1);
});

it('enforces the uncompressed size limit', function (): void {
    config()->set('content-security.archives.max_uncompressed_size', 1024);
    config()->set('content-security.archives.max_compression_ratio', 100000);

    $path = makeZip(static function (ZipArchive $zip): void {
        $zip->addFromString('big.bin', str_repeat('a', 200_000));
    });

    expect(threatNames(ContentSecurity::scanFile($path)))->toContain('archive.uncompressed_size');
});

it('inspects nested archives', function (): void {
    $innerDir = sys_get_temp_dir().'/cs-inner-'.bin2hex(random_bytes(6));
    mkdir($innerDir);
    $inner = $innerDir.'/inner.zip';

    $zip = new ZipArchive;
    $zip->open($inner, ZipArchive::CREATE);
    $zip->addFromString('payload.exe', 'MZ');
    $zip->close();

    $outer = makeZip(static function (ZipArchive $zip) use ($inner): void {
        $zip->addFromString('readme.txt', 'hello');
        $zip->addFile($inner, 'nested.zip');
    });

    // The dangerous entry is one level down; a scanner that only reads the
    // top-level table of contents would call this clean.
    expect(threatNames(ContentSecurity::scanFile($outer)))->toContain('archive.executable_entry');
});

it('does not crash on a malformed archive', function (): void {
    $directory = sys_get_temp_dir().'/cs-bad-'.bin2hex(random_bytes(6));
    mkdir($directory);
    $path = $directory.'/broken.zip';
    file_put_contents($path, "PK\x03\x04".str_repeat("\xff", 400));

    $result = ContentSecurity::scanFile($path);

    // Malformed input must produce a verdict, never an unhandled error.
    expect($result->isClean())->toBeFalse();
});
