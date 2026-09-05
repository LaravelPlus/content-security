<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;
use LaravelPlus\ContentSecurity\Actions\ScanFile;
use LaravelPlus\ContentSecurity\ContentSecurity;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Models\SecurityScan;
use Throwable;

/**
 * Pregled datotek, ki na disku ze lezijo.
 *
 * Pregled vsebine je validacijsko pravilo: vidi tisto, kar mu poda obrazec, in
 * nic drugega. Kar je bilo naloženo, preden je bilo pravilo pripeto -- ali po
 * poti, ki ga nima -- ni bilo pregledano nikoli, in iz baze se tega ne da
 * prebrati, ker zapis o pregledu ne nosi poti do datoteke.
 *
 * Ta ukaz prehodi disk in vsako datoteko, ki je se nihce ni videl, poslje
 * skozi isti cevovod kot nalaganje. Pot se zapise kot ime datoteke, zato je
 * naslednji zagon poceni: kar je bilo pregledano, se preskoci.
 *
 * Okuzena datoteka se v karanteno kopira, ne premakne (glej QuarantineFile),
 * zato pregled starega gradiva ne odnese slike s spletne strani. Z
 * `--no-quarantine` se tudi ta kopija ne naredi in ukaz samo poroca.
 */
final class ScanDiskCommand extends Command
{
    protected $signature = 'content-security:scan-disk
        {disk : Filesystem disk to walk}
        {--path= : Only this directory prefix}
        {--policy= : The file policy to apply}
        {--exclude= : Skip paths matching this regular expression}
        {--limit=0 : Stop after this many scans (0 = no limit)}
        {--rescan : Scan files that already have a scan on file}
        {--no-quarantine : Report findings without copying anything to quarantine}
        {--dry-run : List what would be scanned, scan nothing}
        {--force : Run even when the malware engine reports itself offline}';

    protected $description = 'Scan files already stored on a disk that no scan has seen yet.';

    public function handle(ScanFile $scanner, ContentSecurity $security): int
    {
        $disk = (string) $this->argument('disk');
        $prefix = (string) ($this->option('path') ?? '');
        $policy = is_string($this->option('policy')) ? $this->option('policy') : null;
        $limit = max(0, (int) $this->option('limit'));
        $dryRun = (bool) $this->option('dry-run');

        try {
            $files = Storage::disk($disk)->allFiles($prefix);
        } catch (Throwable $e) {
            $this->components->error(sprintf('Disk [%s] could not be listed: %s', $disk, $e->getMessage()));

            return self::FAILURE;
        }

        if ($files === []) {
            $this->components->info(sprintf('Nothing on [%s]%s.', $disk, $prefix === '' ? '' : ' under '.$prefix));

            return self::SUCCESS;
        }

        // Izpeljanke (pomanjsave, predogledi) nastanejo iz izvirnika na nasem
        // strezniku; ce je izvirnik cist, so ciste tudi one, in prenos vsake
        // razlicice posebej je placan trikrat za isto sliko.
        $exclude = is_string($this->option('exclude')) && $this->option('exclude') !== ''
            ? (string) $this->option('exclude')
            : null;

        if ($exclude !== null) {
            $before = count($files);
            $files = array_values(array_filter(
                $files,
                static fn (string $path): bool => preg_match($exclude, $path) !== 1,
            ));

            $this->components->info(sprintf('Excluded %d of %d paths.', $before - count($files), $before));
        }

        $seen = $this->alreadyScanned($files);
        $rescan = (bool) $this->option('rescan');

        $pending = $rescan
            ? count($files)
            : count(array_filter($files, static fn (string $path): bool => ! isset($seen[$path])));

        // Neuspel pregled velja za nepreverjeno datoteko in gre v karanteno --
        // pravilno pri enem nalaganju, usodno pri sprehodu cez cel disk: en
        // izpad demona bi zapisal karanteno za vsako datoteko posebej. Zato se
        // stanje pogleda, preden se karkoli prenese. Prazen disk in disk, ki je
        // ze ves pregledan, demona ne potrebujeta.
        if ($pending > 0 && ! $dryRun && ! $this->option('force') && ! $this->engineIsUp($security)) {
            $this->components->error('The malware engine is offline — refusing to walk the disk. Fix it, or pass --force.');

            return self::FAILURE;
        }

        $scanned = $skipped = $clean = $flagged = $failed = 0;

        foreach ($files as $path) {
            if (! $rescan && isset($seen[$path])) {
                $skipped++;

                continue;
            }

            if ($limit > 0 && $scanned >= $limit) {
                $skipped++;

                continue;
            }

            if ($dryRun) {
                $this->line('  '.$path);
                $scanned++;

                continue;
            }

            try {
                // Pot in ne golo ime: brez nje naslednji zagon ne ve, kaj je ze
                // videl, in celoten disk se pregleda znova.
                $reference = FileReference::fromDisk($disk, $path, $path);
            } catch (Throwable $e) {
                $this->components->warn(sprintf('%s — unreadable: %s', $path, $e->getMessage()));
                $failed++;

                continue;
            }

            try {
                $result = $scanner->handle($reference, $policy, null, ! $this->option('no-quarantine'));
            } catch (Throwable $e) {
                $this->components->warn(sprintf('%s — scan failed: %s', $path, $e->getMessage()));
                $failed++;

                continue;
            } finally {
                $reference->discardTemporary();
            }

            $scanned++;

            if ($result->isClean()) {
                $clean++;

                continue;
            }

            $flagged++;
            $this->components->warn(sprintf('%s — %s', $path, $result->status()->value));

            foreach ($result->threats() as $threat) {
                $this->line(sprintf('    %s (%s)', $threat->name, $threat->level->value));
            }
        }

        $this->newLine();
        $this->components->twoColumnDetail('Files on disk', (string) count($files));
        $this->components->twoColumnDetail('Already scanned', (string) $skipped);
        $this->components->twoColumnDetail($dryRun ? 'Would scan' : 'Scanned', (string) $scanned);

        if (! $dryRun) {
            $this->components->twoColumnDetail('Clean', (string) $clean);
            $this->components->twoColumnDetail('Findings', (string) $flagged);
            $this->components->twoColumnDetail('Unreadable / errored', (string) $failed);
        }

        // Najdba ni napaka ukaza: ukaz je opravil svoje prav takrat, ko jo
        // najde. Rdec izhod prihranimo za disk, ki ga ni bilo mogoce prebrati.
        return self::SUCCESS;
    }

    /**
     * Ali je dejavni pregledovalnik dosegljiv.
     */
    private function engineIsUp(ContentSecurity $security): bool
    {
        foreach ($security->health() as $health) {
            if ($health->active && $health->online) {
                return true;
            }
        }

        return false;
    }

    /**
     * Poti, ki jih kaksen pregled ze pozna.
     *
     * Poizvedba gre po `original_filename`, ker je to edino polje, ki pot nosi
     * -- zato jo ta ukaz tja tudi zapise.
     *
     * @param  list<string>  $files
     * @return array<string, true>
     */
    private function alreadyScanned(array $files): array
    {
        $seen = [];

        foreach (array_chunk($files, 500) as $chunk) {
            foreach (SecurityScan::query()
                ->where('type', 'file')
                ->whereIn('original_filename', $chunk)
                ->pluck('original_filename') as $path) {
                $seen[(string) $path] = true;
            }
        }

        return $seen;
    }
}
