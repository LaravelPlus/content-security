<?php

declare(strict_types=1);

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Event;
use LaravelPlus\ContentSecurity\Contracts\MalwareScanner;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Events\ScanCompleted;
use LaravelPlus\ContentSecurity\Events\ThreatDetected;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Models\SecurityScan;
use LaravelPlus\ContentSecurity\Tests\Support\FakeMalwareScanner;

function useScanner(MalwareScanner $scanner): void
{
    ContentSecurity::extend('clamav', fn (): MalwareScanner => $scanner);
    config()->set('content-security.malware.default', 'clamav');
    config()->set('content-security.malware.drivers.clamav', ['driver' => 'clamav']);
}

function textFile(string $name, string $contents = 'hello'): string
{
    // No dots in the generated prefix: uniqid(more_entropy: true) contains
    // one, which would trip the double-extension check and make every
    // fixture look suspicious for reasons that have nothing to do with the
    // test.
    $directory = sys_get_temp_dir().'/cs-test-'.bin2hex(random_bytes(6));
    mkdir($directory);
    $path = $directory.'/'.$name;
    file_put_contents($path, $contents);

    return $path;
}

it('passes a clean text file', function (): void {
    useScanner(FakeMalwareScanner::clean());

    $result = ContentSecurity::scanFile(textFile('notes.txt', 'perfectly ordinary'));

    expect($result->isClean())->toBeTrue()
        ->and($result->status())->toBe(ScanStatus::Clean)
        ->and($result->threats())->toBeEmpty();
});

it('rejects an executable extension whatever the policy allows', function (): void {
    useScanner(FakeMalwareScanner::clean());

    $result = ContentSecurity::scanFile(textFile('shell.php', 'plain text'));

    expect($result->isClean())->toBeFalse()
        ->and($result->status())->toBe(ScanStatus::Quarantined);

    $names = array_map(fn ($threat) => $threat->name, $result->threats());
    expect($names)->toContain('file.executable_extension');
});

it('detects PHP hidden inside a file named as an image', function (): void {
    useScanner(FakeMalwareScanner::clean());

    $result = ContentSecurity::scanFile(textFile('avatar.jpg', "<?php system(\$_GET['c']); ?>"));

    expect($result->isClean())->toBeFalse();
});

it('reports an infected file from the engine', function (): void {
    Event::fake([ThreatDetected::class, ScanCompleted::class]);
    forgetResolvedServices();
    useScanner(FakeMalwareScanner::infected('Win.Test.EICAR_HDB-1'));

    $result = ContentSecurity::scanFile(textFile('invoice.pdf', '%PDF-1.4 ordinary'));

    expect($result->isClean())->toBeFalse();

    $names = array_map(fn ($threat) => $threat->name, $result->threats());
    expect($names)->toContain('Win.Test.EICAR_HDB-1');

    Event::assertDispatched(ThreatDetected::class);
});

it('fails closed when the engine is unreachable', function (): void {
    useScanner(FakeMalwareScanner::unavailable());

    $result = ContentSecurity::scanFile(textFile('report.pdf', '%PDF-1.4 ordinary'));

    // The critical assertion of the whole package: a broken scanner must
    // never produce a clean verdict.
    expect($result->isClean())->toBeFalse()
        ->and($result->failed() || $result->status() === ScanStatus::Quarantined)->toBeTrue();
});

it('fails closed when the engine times out', function (): void {
    useScanner(FakeMalwareScanner::timingOut());

    $result = ContentSecurity::scanFile(textFile('report.pdf', '%PDF-1.4 ordinary'));

    expect($result->isClean())->toBeFalse();
});

it('records the scan in the audit trail', function (): void {
    useScanner(FakeMalwareScanner::clean());

    $result = ContentSecurity::scanFile(textFile('notes.txt', 'ordinary'));

    $row = SecurityScan::query()->where('scan_id', (string) $result->scanId())->first();

    expect($row)->not->toBeNull()
        ->and($row->status)->toBe(ScanStatus::Clean)
        ->and($row->original_filename)->toContain('notes.txt')
        ->and($row->checksum_sha256)->toHaveLength(64);
});

it('rejects a file above the policy size limit', function (): void {
    useScanner(FakeMalwareScanner::clean());
    config()->set('content-security.files.policies.default.max_size', 10);

    $result = ContentSecurity::scanFile(textFile('big.txt', str_repeat('x', 500)));

    expect($result->isClean())->toBeFalse();
});

it('scans an uploaded file', function (): void {
    useScanner(FakeMalwareScanner::clean());

    $result = ContentSecurity::scanFile(UploadedFile::fake()->create('doc.pdf', 4, 'application/pdf'));

    expect($result->scanId())->not->toBeNull();
});

it('accepts a genuine image whose browser Content-Type disagrees with its bytes', function (): void {
    useScanner(FakeMalwareScanner::clean());

    $png = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==');
    $path = textFile('avatar.png', $png);

    // Exactly what a real upload looks like when the browser declares
    // application/octet-stream: the declared type disagrees with the sniffed
    // one. That is routine, it is recorded as Info, and it must not reject
    // the upload — this used to fail every such avatar.
    $file = new UploadedFile($path, 'avatar.png', null, null, true);

    $result = ContentSecurity::scanFile($file, 'images');

    expect($result->isClean())->toBeTrue()
        ->and($result->status())->toBe(ScanStatus::Clean);

    $names = array_map(fn ($threat) => $threat->name, $result->threats());

    // Recorded, not acted on.
    expect($names)->toContain('file.declared_mime_mismatch');
});

it('still rejects a polyglot image with PHP appended', function (): void {
    useScanner(FakeMalwareScanner::clean());

    $png = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==');
    $path = textFile('avatar.png', $png."\n<?php system(\$_GET['c']); ?>");

    $file = new UploadedFile($path, 'avatar.png', null, null, true);

    // Laravel's own `image` and `mimes` rules pass this — getimagesize()
    // only reads the header.
    expect(ContentSecurity::scanFile($file, 'images')->isClean())->toBeFalse();
});
