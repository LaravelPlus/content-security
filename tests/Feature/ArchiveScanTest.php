<?php

declare(strict_types=1);

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
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
    config()->set('content-security.malware.default', 'none');
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

/** One ustar entry: a 512-byte header plus its data padded to a whole block. */
function tarEntry(string $name, string $data = '', string $type = '0', string $link = ''): string
{
    $header = str_pad($name, 100, "\0")
        .str_pad('0000644', 8, "\0").str_pad('0000000', 8, "\0").str_pad('0000000', 8, "\0")
        .sprintf('%011o', strlen($data))."\0".sprintf('%011o', 0)."\0"
        .str_repeat(' ', 8).$type.str_pad($link, 100, "\0")
        ."ustar\0".'00'.str_repeat("\0", 247);
    $header = substr_replace($header, sprintf("%06o\0 ", array_sum(unpack('C*', $header))), 148, 8);

    return $header.str_pad($data, (int) ceil(strlen($data) / 512) * 512, "\0");
}

/**
 * Written to an extensionless temp path, as PHP stores a real upload (#5).
 *
 * @param  list<string>  $entries
 */
function tarUpload(array $entries, bool $gzip = true): UploadedFile
{
    $path = tempnam(sys_get_temp_dir(), 'php');
    $tar = implode('', $entries).str_repeat("\0", 1024);
    file_put_contents($path, $gzip ? gzencode($tar, 9) : $tar);

    return new UploadedFile($path, $gzip ? 'upload.tar.gz' : 'upload.tar', null, null, true);
}

it('inspects tar and tar.gz uploads stored without an extension', function (bool $gzip): void {
    config()->set('content-security.files.policies.default.extensions', ['tar', 'gz']);

    $clean = ContentSecurity::scanFile(tarUpload([tarEntry('docs/', '', '5'), tarEntry('docs/readme.txt', 'hello')], $gzip));
    $evil = ContentSecurity::scanFile(tarUpload([tarEntry('../../etc/cron.d/x', 'evil'), tarEntry('setup.exe', 'MZ')], $gzip));

    // `.tar.gz` still draws the policy's low multiple-extension note; the archive itself is clean.
    expect(array_filter(threatNames($clean), static fn (string $name): bool => str_starts_with($name, 'archive.')))->toBe([])
        ->and(threatNames($evil))->toContain('archive.path_traversal', 'archive.executable_entry')
        ->and(threatNames($evil))->not->toContain('archive.unreadable');
})->with(['tar' => false, 'tar.gz' => true]);

it('flags a tar symlink that points outside the extraction root', function (): void {
    $result = ContentSecurity::scanFile(tarUpload([tarEntry('passwd', '', '2', '/etc/passwd')]));

    expect(threatNames($result))->toContain('archive.path_traversal');
});

it('reads long tar names from GNU and PAX headers', function (): void {
    $long = str_repeat('a/', 60).'payload.exe';

    $gnu = ContentSecurity::scanFile(tarUpload([tarEntry('././@LongLink', $long."\0", 'L'), tarEntry('short', 'MZ')]));
    $pax = ContentSecurity::scanFile(tarUpload([tarEntry('PaxHeader', sprintf('%d path=%s', strlen($long) + 13, $long)."\n", 'x'), tarEntry('short', 'MZ')]));

    expect(threatNames($gnu))->toContain('archive.executable_entry')
        ->and(threatNames($pax))->toContain('archive.executable_entry');
});

it('enforces tar.gz limits before inflating past them', function (): void {
    config()->set('content-security.archives.max_uncompressed_size', 1024 * 1024);
    config()->set('content-security.archives.max_files', 3);

    // ~20 MB of zeros gzips to ~20 KB; the second entry is never inflated.
    $bomb = ContentSecurity::scanFile(tarUpload([tarEntry('a.bin', str_repeat("\0", 10 * 1024 * 1024)), tarEntry('b.bin', str_repeat("\0", 10 * 1024 * 1024))]));
    $many = ContentSecurity::scanFile(tarUpload(array_map(static fn (int $i): string => tarEntry("f{$i}.txt", 'x'), range(1, 10))));

    expect(threatNames($bomb))->toContain('archive.uncompressed_size', 'archive.compression_bomb')
        ->and(threatNames($many))->toContain('archive.too_many_files');
});

it('fails closed on a tar.gz that cannot be read', function (string $bytes): void {
    Storage::fake('quarantine');
    $path = tempnam(sys_get_temp_dir(), 'php');
    file_put_contents($path, $bytes);

    $result = ContentSecurity::scanFile(new UploadedFile($path, 'upload.tar.gz', null, null, true));

    expect(threatNames($result))->toContain('archive.unreadable')
        ->and($result->isClean())->toBeFalse()
        ->and($result->status())->toBe(ScanStatus::Quarantined);
})->with([
    'not a tar inside' => [gzencode(str_repeat('not a tar ', 200))],
    'truncated' => [gzencode(substr(tarEntry('a.txt', str_repeat('x', 4096)), 0, 1500))],
    'corrupt gzip' => ["\x1f\x8b\x08\x00".str_repeat("\xff", 600)],
]);
