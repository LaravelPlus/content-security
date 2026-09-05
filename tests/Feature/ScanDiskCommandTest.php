<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Storage;
use LaravelPlus\ContentSecurity\Contracts\MalwareScanner;
use LaravelPlus\ContentSecurity\Models\SecurityScan;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Tests\Support\FakeMalwareScanner;

/**
 * Pregled tega, kar na disku ze lezi.
 *
 * Datoteke, nalozene preden je bilo pravilo pripeto, pregleda ni videl nikoli
 * -- in iz baze se tega ne da prebrati, ker zapis o pregledu ne nosi poti.
 */
function useDiskScanner(MalwareScanner $scanner): void
{
    ContentSecurity::extend('clamav', fn (): MalwareScanner => $scanner);
    config()->set('content-security.malware.default', 'clamav');
    config()->set('content-security.malware.drivers.clamav', ['driver' => 'clamav']);
}

function seedDisk(int $files = 2): void
{
    Storage::fake('uploads');

    foreach (range(1, $files) as $i) {
        Storage::disk('uploads')->put("logos/slika{$i}.txt", "vsebina {$i}");
    }
}

it('scans every file the disk holds', function (): void {
    useDiskScanner(FakeMalwareScanner::clean());
    seedDisk();

    $this->artisan('content-security:scan-disk uploads')->assertSuccessful();

    expect(SecurityScan::query()->where('type', 'file')->count())->toBe(2)
        // Pot in ne golo ime: brez nje naslednji zagon ne ve, kaj je ze videl.
        ->and(SecurityScan::query()->pluck('original_filename')->all())
        ->toEqualCanonicalizing(['logos/slika1.txt', 'logos/slika2.txt']);
});

it('skips what it has already seen', function (): void {
    useDiskScanner(FakeMalwareScanner::clean());
    seedDisk();

    $this->artisan('content-security:scan-disk uploads')->assertSuccessful();
    $this->artisan('content-security:scan-disk uploads')->assertSuccessful();

    // Drugi zagon ne sme placati istega pregleda znova.
    expect(SecurityScan::query()->count())->toBe(2);
});

it('scans again when told to', function (): void {
    useDiskScanner(FakeMalwareScanner::clean());
    seedDisk(1);

    $this->artisan('content-security:scan-disk uploads')->assertSuccessful();
    $this->artisan('content-security:scan-disk uploads --rescan')->assertSuccessful();

    expect(SecurityScan::query()->count())->toBe(2);
});

it('walks only the directory it was given', function (): void {
    useDiskScanner(FakeMalwareScanner::clean());
    Storage::fake('uploads');
    Storage::disk('uploads')->put('logos/a.txt', 'a');
    Storage::disk('uploads')->put('photos/b.txt', 'b');

    $this->artisan('content-security:scan-disk uploads --path=logos')->assertSuccessful();

    expect(SecurityScan::query()->pluck('original_filename')->all())->toBe(['logos/a.txt']);
});

it('stops at the limit it was given', function (): void {
    useDiskScanner(FakeMalwareScanner::clean());
    seedDisk(3);

    $this->artisan('content-security:scan-disk uploads --limit=1')->assertSuccessful();

    expect(SecurityScan::query()->count())->toBe(1);
});

it('lists without scanning on a dry run', function (): void {
    useDiskScanner(FakeMalwareScanner::clean());
    seedDisk();

    $this->artisan('content-security:scan-disk uploads --dry-run')->assertSuccessful();

    expect(SecurityScan::query()->count())->toBe(0);
});

it('reports a finding and keeps the original where it is', function (): void {
    useDiskScanner(FakeMalwareScanner::infected());
    seedDisk(1);

    $this->artisan('content-security:scan-disk uploads')->assertSuccessful();

    $scan = SecurityScan::query()->sole();

    expect($scan->status->value)->not->toBe('clean')
        // Karantena datoteko kopira, ne premakne: pregled starega gradiva ne
        // sme odnesti slike s spletne strani.
        ->and(Storage::disk('uploads')->exists('logos/slika1.txt'))->toBeTrue();
});

it('can report without copying anything to quarantine', function (): void {
    useDiskScanner(FakeMalwareScanner::infected());
    seedDisk(1);

    $this->artisan('content-security:scan-disk uploads --no-quarantine')->assertSuccessful();

    expect(SecurityScan::query()->sole()->quarantine_path)->toBeNull();
});

it('says so when the disk is empty', function (): void {
    Storage::fake('uploads');

    $this->artisan('content-security:scan-disk uploads')->assertSuccessful();

    expect(SecurityScan::query()->count())->toBe(0);
});

it('fails loudly on a disk that cannot be listed', function (): void {
    $this->artisan('content-security:scan-disk ni-takega-diska')->assertFailed();
});

it('can leave derived variants alone', function (): void {
    useDiskScanner(FakeMalwareScanner::clean());
    Storage::fake('uploads');
    Storage::disk('uploads')->put('logos/a.webp', 'izvirnik');
    Storage::disk('uploads')->put('logos/a.96.webp', 'pomanjsava');
    Storage::disk('uploads')->put('logos/a.256.webp', 'pomanjsava');

    $this->artisan('content-security:scan-disk uploads --exclude=/\.(96|256)\./')->assertSuccessful();

    // Izpeljanka nastane iz izvirnika na nasem strezniku; cist izvirnik pomeni
    // cisto izpeljanko, prenos vsake posebej pa je placan trikrat.
    expect(SecurityScan::query()->pluck('original_filename')->all())->toBe(['logos/a.webp']);
});

it('refuses to walk the disk when the engine is offline', function (): void {
    useDiskScanner(FakeMalwareScanner::unavailable());
    seedDisk(2);

    // Neuspel pregled velja za nepreverjeno datoteko in gre v karanteno --
    // pravilno pri enem nalaganju, usodno pri sprehodu cez cel disk.
    $this->artisan('content-security:scan-disk uploads')->assertFailed();

    expect(SecurityScan::query()->count())->toBe(0);
});

it('walks anyway when forced', function (): void {
    useDiskScanner(FakeMalwareScanner::unavailable());
    seedDisk(1);

    $this->artisan('content-security:scan-disk uploads --force')->assertSuccessful();

    expect(SecurityScan::query()->count())->toBe(1);
});

it('lists on a dry run without asking the engine anything', function (): void {
    useDiskScanner(FakeMalwareScanner::unavailable());
    seedDisk(1);

    $this->artisan('content-security:scan-disk uploads --dry-run')->assertSuccessful();
});

it('does not need the engine when everything is already scanned', function (): void {
    useDiskScanner(FakeMalwareScanner::clean());
    seedDisk(1);

    $this->artisan('content-security:scan-disk uploads')->assertSuccessful();

    // Drugi zagon nima kaj prenasati, zato mu je stanje demona vseeno.
    useDiskScanner(FakeMalwareScanner::unavailable());

    $this->artisan('content-security:scan-disk uploads')->assertSuccessful();
});

it('remembers where the file lives so the console can show it', function (): void {
    useDiskScanner(FakeMalwareScanner::clean());
    Storage::fake('uploads');
    Storage::disk('uploads')->put('logos/a.webp', 'vsebina');

    $this->artisan('content-security:scan-disk uploads')->assertSuccessful();

    $scan = SecurityScan::query()->sole();

    // Brez tega bi konzola vedela, da je slika cista, ne pa katera.
    expect($scan->metadata['disk'] ?? null)->toBe('uploads')
        ->and($scan->metadata['disk_path'] ?? null)->toBe('logos/a.webp');
});
