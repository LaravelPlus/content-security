<?php

declare(strict_types=1);

use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Storage;
use LaravelPlus\ContentSecurity\Actions\ReleaseQuarantinedFile;
use LaravelPlus\ContentSecurity\Actions\ScanFile;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Events\FileQuarantined;
use LaravelPlus\ContentSecurity\Events\QuarantineReleased;
use LaravelPlus\ContentSecurity\Exceptions\QuarantineException;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Jobs\ScanFileJob;
use LaravelPlus\ContentSecurity\Models\QuarantineRelease;
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

it('allows an audited override that keeps the real verdict', function (): void {
    Storage::fake('quarantine');
    Storage::fake('releases');
    Event::fake([QuarantineReleased::class]);

    $result = ContentSecurity::scanFile(dangerousFile());
    $scan = SecurityScan::query()->where('scan_id', (string) $result->scanId())->firstOrFail();
    $checksum = hash('sha256', Storage::disk('quarantine')->get((string) $scan->quarantine_path));

    app(ReleaseQuarantinedFile::class)->handle($scan, 'releases', 'ok/file.bin', 'user-1', override: true, reason: 'False positive, reviewed by security');

    Storage::disk('releases')->assertExists('ok/file.bin');
    $fresh = $scan->fresh();
    $release = QuarantineRelease::query()->where('scan_id', $scan->scan_id)->sole();

    // Released, but never relabelled: the scan still says what the rescan found.
    expect($fresh->isQuarantined())->toBeFalse()
        ->and($fresh->status)->not->toBe(ScanStatus::Clean)
        ->and($release->overridden)->toBeTrue()
        ->and($release->reason)->toBe('False positive, reviewed by security')
        ->and($release->actor_id)->toBe('user-1')
        ->and($release->scan_status)->toBe($fresh->status)
        ->and($release->checksum_sha256)->toBe($checksum)
        ->and($release->created_at)->not->toBeNull();

    Event::assertDispatched(QuarantineReleased::class, static fn (QuarantineReleased $event): bool => $event->overridden
        && $event->reason === 'False positive, reviewed by security'
        && $event->scanStatus === $fresh->status);
});

it('refuses an override without a reason', function (?string $reason): void {
    Storage::fake('quarantine');
    Storage::fake('releases');

    $result = ContentSecurity::scanFile(dangerousFile());
    $scan = SecurityScan::query()->where('scan_id', (string) $result->scanId())->firstOrFail();

    expect(fn () => app(ReleaseQuarantinedFile::class)->handle($scan, 'releases', 'ok/file.bin', 'user-1', override: true, reason: $reason))
        ->toThrow(QuarantineException::class);

    Storage::disk('releases')->assertMissing('ok/file.bin');
    expect($scan->fresh()->isQuarantined())->toBeTrue()
        ->and(QuarantineRelease::query()->count())->toBe(0);
})->with(['missing' => [null], 'blank' => ['   ']]);

it('records a clean release too, and the record is immutable', function (): void {
    Storage::fake('quarantine');
    Storage::fake('releases');

    $clean = ContentSecurity::scanFile(cleanFile());
    // Force a quarantine the way a queued upload sits in it before its verdict.
    $scan = SecurityScan::query()->where('scan_id', (string) $clean->scanId())->firstOrFail();
    $path = 'content-security/quarantine/'.$scan->scan_id.'.quarantined';
    Storage::disk('quarantine')->put($path, 'ordinary content');
    $scan->forceFill(['status' => ScanStatus::Quarantined->value, 'quarantine_disk' => 'quarantine', 'quarantine_path' => $path])->save();

    app(ReleaseQuarantinedFile::class)->handle($scan, 'releases', 'ok/notes.txt', 'user-2');

    $release = QuarantineRelease::query()->where('scan_id', $scan->scan_id)->sole();
    expect($scan->fresh()->status)->toBe(ScanStatus::Clean)
        ->and($release->overridden)->toBeFalse()
        ->and($release->scan_status)->toBe(ScanStatus::Clean)
        ->and(fn () => $release->update(['reason' => 'edited']))->toThrow(LogicException::class)
        ->and(fn () => $release->delete())->toThrow(LogicException::class);
});

it('leaves the file quarantined and unaudited when the copy fails', function (): void {
    Storage::fake('quarantine');

    $result = ContentSecurity::scanFile(dangerousFile());
    $scan = SecurityScan::query()->where('scan_id', (string) $result->scanId())->firstOrFail();

    $path = (string) $scan->quarantine_path;
    $broken = Mockery::mock(Filesystem::class);
    $broken->shouldReceive('writeStream')->andReturn(false);
    Storage::set('broken', $broken);

    expect(fn () => app(ReleaseQuarantinedFile::class)->handle($scan, 'broken', 'ok/file.bin', 'user-1', override: true, reason: 'reviewed'))
        ->toThrow(QuarantineException::class);

    Storage::disk('quarantine')->assertExists($path);
    expect($scan->isQuarantined())->toBeTrue()
        ->and($scan->fresh()->isQuarantined())->toBeTrue()
        ->and($scan->fresh()->status)->toBe(ScanStatus::Quarantined)
        ->and(QuarantineRelease::query()->count())->toBe(0);
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
