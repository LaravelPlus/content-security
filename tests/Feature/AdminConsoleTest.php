<?php

declare(strict_types=1);

use Illuminate\Foundation\Auth\User as AuthUser;
use Illuminate\Support\Facades\Storage;
use LaravelPlus\ContentSecurity\Contracts\PolicyRepository;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Models\SecurityScan;

final class ConsoleUser extends AuthUser
{
    protected $table = 'users';

    protected $guarded = [];

    public bool $admin = false;
}

function consoleUser(bool $admin = true): ConsoleUser
{
    $user = new ConsoleUser(['id' => 1, 'name' => 'Tester', 'email' => 'tester@example.com']);
    $user->admin = $admin;
    $user->exists = true;

    return $user;
}

it('denies the console when no authorization has been configured', function (): void {
    // The default must be deny. A security console that opens because
    // nobody configured it would be the vulnerability it exists to prevent.
    $this->actingAs(consoleUser())
        ->get('/admin/content-security')
        ->assertNotFound();
});

it('denies a user the callback rejects', function (): void {
    ContentSecurity::auth(fn (?ConsoleUser $user): bool => (bool) $user?->admin);

    $this->actingAs(consoleUser(admin: false))
        ->get('/admin/content-security')
        ->assertNotFound();
});

it('denies a guest', function (): void {
    ContentSecurity::auth(fn (?ConsoleUser $user): bool => (bool) $user?->admin);

    $this->get('/admin/content-security')->assertNotFound();
});

it('answers 404 rather than 403', function (): void {
    ContentSecurity::auth(fn (): bool => false);

    // Confirming that a security console exists at this URL is itself
    // information an unauthorised visitor should not get.
    $this->actingAs(consoleUser())
        ->get('/admin/content-security')
        ->assertStatus(404);
});

it('allows a user the callback accepts', function (): void {
    ContentSecurity::auth(fn (?ConsoleUser $user): bool => (bool) $user?->admin);

    $this->actingAs(consoleUser())
        ->getJson('/admin/content-security')
        ->assertOk()
        ->assertJsonStructure(['statistics', 'posture', 'health', 'recentScans']);
});

it('serves every console page', function (string $path): void {
    ContentSecurity::auth(fn (): bool => true);

    $this->actingAs(consoleUser())->getJson($path)->assertOk();
})->with([
    '/admin/content-security',
    '/admin/content-security/scans',
    '/admin/content-security/threats',
    '/admin/content-security/quarantine',
    '/admin/content-security/policies',
    '/admin/content-security/health',
]);

it('serves a scan detail page', function (): void {
    ContentSecurity::auth(fn (): bool => true);

    $result = ContentSecurity::scanText('An ordinary sentence.');

    $this->actingAs(consoleUser())
        ->getJson('/admin/content-security/scans/'.$result->scanId())
        ->assertOk()
        ->assertJsonPath('scan.id', (string) $result->scanId());
});

it('hides filesystem paths unless explicitly exposed', function (): void {
    ContentSecurity::auth(fn (): bool => true);
    Storage::fake('quarantine');

    $directory = sys_get_temp_dir().'/cs-admin-'.bin2hex(random_bytes(6));
    mkdir($directory);
    file_put_contents($directory.'/shell.php', '<?php echo 1;');

    $result = ContentSecurity::scanFile($directory.'/shell.php');

    $response = $this->actingAs(consoleUser())
        ->getJson('/admin/content-security/scans/'.$result->scanId())
        ->assertOk();

    expect($response->json('scan'))->not->toHaveKey('quarantine_path');

    config()->set('content-security.admin.expose_paths', true);

    $exposed = $this->actingAs(consoleUser())
        ->getJson('/admin/content-security/scans/'.$result->scanId())
        ->assertOk();

    expect($exposed->json('scan.quarantine_path'))->toBeString();
});

it('bounds the per-page parameter', function (): void {
    ContentSecurity::auth(fn (): bool => true);

    // Unbounded pagination is a denial-of-service parameter wearing a
    // convenience costume.
    $response = $this->actingAs(consoleUser())
        ->getJson('/admin/content-security/scans?per_page=100000')
        ->assertOk();

    expect($response->json('scans.meta.per_page'))->toBeLessThanOrEqual(100);
});

it('filters scans by status', function (): void {
    ContentSecurity::auth(fn (): bool => true);

    ContentSecurity::scanText('An ordinary sentence.');
    ContentSecurity::scanText('<script>alert(1)</script>');

    $response = $this->actingAs(consoleUser())
        ->getJson('/admin/content-security/scans?status=clean')
        ->assertOk();

    $statuses = array_column($response->json('scans.data'), 'status');

    expect($statuses)->not->toBeEmpty()
        ->and(array_unique($statuses))->toBe(['clean']);
});

it('rejects a policy override that would allow an executable extension', function (): void {
    ContentSecurity::auth(fn (): bool => true);

    $this->actingAs(consoleUser())
        ->putJson('/admin/content-security/policies/default', [
            'type' => 'file',
            'extensions' => ['pdf', 'php'],
        ])
        ->assertStatus(422)
        ->assertJsonValidationErrors('extensions');

    expect(SecurityScan::query()->count())->toBe(0);
});

it('rejects a policy override above the size ceiling', function (): void {
    ContentSecurity::auth(fn (): bool => true);
    config()->set('content-security.files.max_size_ceiling', 1024 * 1024);

    $this->actingAs(consoleUser())
        ->putJson('/admin/content-security/policies/default', [
            'type' => 'file',
            'max_size' => 900 * 1024 * 1024,
        ])
        ->assertStatus(422)
        ->assertJsonValidationErrors('max_size');
});

it('accepts a legitimate policy override', function (): void {
    ContentSecurity::auth(fn (): bool => true);

    $this->actingAs(consoleUser())
        ->put('/admin/content-security/policies/default', [
            'type' => 'file',
            'max_size' => 5 * 1024 * 1024,
            'note' => 'Tightened after review',
        ])
        ->assertRedirect();

    expect(app(PolicyRepository::class)->file('default')->maxSize)
        ->toBe(5 * 1024 * 1024);
});
