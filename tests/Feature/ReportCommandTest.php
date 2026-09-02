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
