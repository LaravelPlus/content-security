<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Storage;
use LaravelPlus\ContentSecurity\Http\Resources\ScanResource;
use LaravelPlus\ContentSecurity\Models\SecurityScan;

/**
 * Kaj je bilo pregledano: "clean" ob imenu datoteke je podatek brez obraza.
 */
function scanRow(array $attributes = []): SecurityScan
{
    return SecurityScan::query()->create(array_merge([
        'scan_id' => (string) Illuminate\Support\Str::ulid(),
        'type' => 'file',
        'status' => 'clean',
        'original_filename' => 'logos/a.webp',
        'detected_mime' => 'image/webp',
        'file_size' => 1234,
    ], $attributes));
}

function previewOf(SecurityScan $scan): array
{
    return (new ScanResource($scan))->toArray(request())['preview'];
}

it('offers an image that is still on the disk', function (): void {
    Storage::fake('uploads');
    Storage::disk('uploads')->put('logos/a.webp', 'vsebina');

    $preview = previewOf(scanRow(['metadata' => ['disk' => 'uploads', 'disk_path' => 'logos/a.webp']]));

    expect($preview['kind'])->toBe('image')
        ->and($preview['url'])->toBeString();
});

it('has nothing to show for an upload, which was scanned before it was stored', function (): void {
    $preview = previewOf(scanRow(['original_filename' => 'nejc.jpeg']));

    expect($preview['kind'])->toBe('image')
        ->and($preview['url'])->toBeNull();
});

it('has nothing to show when the file has since been deleted', function (): void {
    Storage::fake('uploads');

    $preview = previewOf(scanRow(['metadata' => ['disk' => 'uploads', 'disk_path' => 'logos/izbrisana.webp']]));

    expect($preview['url'])->toBeNull();
});

it('names the kind so the console can pick an icon', function (string $mime, string $kind): void {
    expect(previewOf(scanRow(['detected_mime' => $mime]))['kind'])->toBe($kind);
})->with([
    ['image/png', 'image'],
    ['application/pdf', 'pdf'],
    ['text/plain', 'text'],
    ['application/zip', 'archive'],
    ['application/octet-stream', 'file'],
]);

it('treats a text scan as text even without a mime type', function (): void {
    $scan = scanRow(['type' => 'text', 'status' => 'clean', 'detected_mime' => null, 'original_filename' => null]);

    expect(previewOf($scan)['kind'])->toBe('text');
});
