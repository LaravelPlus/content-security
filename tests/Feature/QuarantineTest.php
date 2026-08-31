<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Storage;
use LaravelPlus\ContentSecurity\Actions\ReleaseQuarantinedFile;
use LaravelPlus\ContentSecurity\Actions\ScanFile;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Events\FileQuarantined;
use LaravelPlus\ContentSecurity\Exceptions\QuarantineException;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Jobs\ScanFileJob;
use LaravelPlus\ContentSecurity\Models\SecurityScan;

function dangerousFile(string $name = 'shell.php'): string
{
    $directory = sys_get_temp_dir().'/cs-q-'.bin2hex(random_bytes(6));
    mkdir($directory);
    $path = $directory.'/'.$name;
    file_put_contents($path, '<?php system($_GET["c"]);');

    return $path;
}

function cleanFile(string $name = 'notes.txt'): string
{
    $directory = sys_get_temp_dir().'/cs-q-'.bin2hex(random_bytes(6));
    mkdir($directory);
    $path = $directory.'/'.$name;
    file_put_contents($path, 'ordinary content');

    return $path;
}

it('moves a rejected file into quarantine storage', function (): void {
    Storage::fake('quarantine');

    $result = ContentSecurity::scanFile(dangerousFile());

    expect($result->status())->toBe(ScanStatus::Quarantined);

    $scan = SecurityScan::query()->where('scan_id', (string) $result->scanId())->firstOrFail();

    expect($scan->isQuarantined())->toBeTrue();
    Storage::disk('quarantine')->assertExists((string) $scan->quarantine_path);
});

it('never uses the uploader filename as the stored path', function (): void {
    Storage::fake('quarantine');

    // The hostile name cannot be a real path on disk — that is the point.
    // It arrives the way it actually does in production: as the *claimed*
    // original name on an upload whose real location we chose.
    $reference = FileReference::fromPath(
        dangerousFile('upload.bin'),
        '../../etc/evil.php',
    );

    $result = ContentSecurity::scanFile($reference);

    $scan = SecurityScan::query()->where('scan_id', (string) $result->scanId())->firstOrFail();
    $path = (string) $scan->quarantine_path;

    // Traversal, the original name and the executable extension must all be
    // absent from the physical path — it is a generated ULID.
    expect($path)->not->toContain('..')
        ->and($path)->not->toContain('etc/')
        ->and($path)->toStartWith('content-security/quarantine/')
        ->and($path)->toEndWith('.quarantined')
        // The original name survives as metadata, where it can be read but
        // never obeyed.
        ->and($scan->original_filename)->toContain('evil.php');
});

it('dispatches a quarantine event', function (): void {
    Storage::fake('quarantine');
    Event::fake([FileQuarantined::class]);
    forgetResolvedServices();

    ContentSecurity::scanFile(dangerousFile());

    Event::assertDispatched(FileQuarantined::class);
});

it('refuses to release a file that is still not clean', function (): void {
    Storage::fake('quarantine');

    $result = ContentSecurity::scanFile(dangerousFile());
    $scan = SecurityScan::query()->where('scan_id', (string) $result->scanId())->firstOrFail();

    Storage::fake('releases');

    expect(fn () => app(ReleaseQuarantinedFile::class)->handle($scan, 'releases', 'ok/shell.php'))
        ->toThrow(QuarantineException::class);

    Storage::disk('releases')->assertMissing('ok/shell.php');
});

it('allows an audited override', function (): void {
    Storage::fake('quarantine');
    Storage::fake('releases');

    $result = ContentSecurity::scanFile(dangerousFile());
    $scan = SecurityScan::query()->where('scan_id', (string) $result->scanId())->firstOrFail();

    app(ReleaseQuarantinedFile::class)->handle($scan, 'releases', 'ok/file.bin', 'user-1', override: true);

    Storage::disk('releases')->assertExists('ok/file.bin');
    expect($scan->fresh()->isQuarantined())->toBeFalse();
});

it('deletes a quarantined file but keeps its scan record', function (): void {
    Storage::fake('quarantine');

    $result = ContentSecurity::scanFile(dangerousFile());
    $scan = SecurityScan::query()->where('scan_id', (string) $result->scanId())->firstOrFail();
    $path = (string) $scan->quarantine_path;

    app(ReleaseQuarantinedFile::class)->delete($scan, 'user-1');

    Storage::disk('quarantine')->assertMissing($path);

    // The audit trail outlives the artefact.
    expect(SecurityScan::query()->where('scan_id', (string) $result->scanId())->exists())->toBeTrue();
});

it('quarantines first, then queues the scan', function (): void {
    Storage::fake('quarantine');
    Bus::fake();
    forgetResolvedServices();

    $scanId = ContentSecurity::queue(cleanFile());

    // An unscanned upload must never wait for its verdict in normal storage.
    Bus::assertDispatched(ScanFileJob::class, static fn (ScanFileJob $job): bool => (string) $job->scanId === (string) $scanId);

    expect(Storage::disk('quarantine')->allFiles())->not->toBeEmpty();
});

it('is idempotent on the scan id when the job runs', function (): void {
    Storage::fake('quarantine');

    $scanId = ContentSecurity::queue(cleanFile());
    $path = Storage::disk('quarantine')->allFiles()[0];

    $job = new ScanFileJob($scanId, 'quarantine', $path, 'notes.txt', null);

    $job->handle(app(ScanFile::class), app(ScanRepository::class));
    $job->handle(app(ScanFile::class), app(ScanRepository::class));

    // Two runs, one audit row — the scan id is fixed by the caller.
    expect(SecurityScan::query()->where('scan_id', (string) $scanId)->count())->toBe(1);
});

it('marks a scan failed when the job exhausts its retries', function (): void {
    Storage::fake('quarantine');

    $scanId = ContentSecurity::queue(cleanFile());
    $path = Storage::disk('quarantine')->allFiles()[0];

    (new ScanFileJob($scanId, 'quarantine', $path, 'notes.txt', null))->failed(new RuntimeException('boom'));

    // A row left saying "scanning" for ever is a scan the application can
    // never treat as failed, which defeats fail-closed.
    expect(SecurityScan::query()->where('scan_id', (string) $scanId)->value('status'))
        ->toBe(ScanStatus::Failed);
});
