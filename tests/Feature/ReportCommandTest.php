<?php

declare(strict_types=1);

it('renders the digest mail view without a missing mail:: hint path error', function (): void {
    // No Mail::fake(): the bug only reproduces when the view actually
    // renders, and MailFake never touches the rendering path for
    // notification-built (non-Mailable) messages. The default testbench
    // mailer is `log`, so this exercises real rendering without a network
    // call.
    $this
        ->artisan('content-security:report', [
            '--period' => 'daily',
            '--to' => ['ops@example.test'],
            '--force' => true,
        ])
        ->assertExitCode(0);
});

it('lists the concrete failed scan and carries the verdict in the subject', function (): void {
    \LaravelPlus\ContentSecurity\Models\SecurityScan::query()->create([
        'scan_id' => 'test-1',
        'type' => 'file',
        'status' => 'failed',
        'policy' => 'images',
        'original_filename' => 'cv.pdf',
        'user_id' => '42',
        'metadata' => ['error' => 'ClamAV socket unreachable'],
        'created_at' => now()->subDay(),
    ]);

    $report = \LaravelPlus\ContentSecurity\Reports\SecurityReport::build(
        'daily', now()->subDays(2)->toImmutable(), now()->toImmutable(),
    );
    $mail = (new \LaravelPlus\ContentSecurity\Notifications\SecurityDigest($report))
        ->toMail(new \Illuminate\Notifications\AnonymousNotifiable);
    $html = (string) $mail->render();

    expect($report->worthSending())->toBeTrue()
        ->and($mail->subject)->toContain('failed scans 1')
        ->and($html)->toContain('cv.pdf', 'user 42', 'ClamAV socket unreachable')
        ->and($html)->not->toContain('Average scan time');
});

it('skips a daily report with only suspicious scans but keeps the weekly', function (): void {
    \LaravelPlus\ContentSecurity\Models\SecurityScan::query()->create([
        'scan_id' => 'test-2', 'type' => 'file', 'status' => 'suspicious', 'created_at' => now()->subDay(),
    ]);

    $daily = \LaravelPlus\ContentSecurity\Reports\SecurityReport::build('daily', now()->subDays(2)->toImmutable(), now()->toImmutable());
    $weekly = \LaravelPlus\ContentSecurity\Reports\SecurityReport::build('weekly', now()->subDays(2)->toImmutable(), now()->toImmutable());

    expect($daily->worthSending())->toBeFalse()->and($weekly->worthSending())->toBeTrue();
});

it('treats an offline active scanner as news only while scanning is enabled', function (): void {
    $offline = [\LaravelPlus\ContentSecurity\Support\ScannerHealth::offline('clamav', 'clamd did not answer PING.')->asActive()];
    $build = fn () => \LaravelPlus\ContentSecurity\Reports\SecurityReport::build(
        'daily', now()->subDays(2)->toImmutable(), now()->toImmutable(), $offline,
    );

    expect($build()->worthSending())->toBeTrue();

    config(['content-security.enabled' => false]);

    expect($build()->worthSending())->toBeFalse();
});
