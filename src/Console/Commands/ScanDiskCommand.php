<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;
use LaravelPlus\ContentSecurity\Actions\ScanFile;
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
        {--limit=0 : Stop after this many scans (0 = no limit)}
        {--rescan : Scan files that already have a scan on file}
        {--no-quarantine : Report findings without copying anything to quarantine}
        {--dry-run : List what would be scanned, scan nothing}';

    protected $description = 'Scan files already stored on a disk that no scan has seen yet.';

    public function handle(ScanFile $scanner): int
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

        $seen = $this->alreadyScanned($files);
        $rescan = (bool) $this->option('rescan');

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
