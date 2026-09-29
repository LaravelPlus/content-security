<?php

declare(strict_types=1);

return [
    'daily_subject' => 'Content Security — :verdict (:date)',
    'weekly_subject' => 'Content Security — week :from–:to: :verdict',
    'ok' => 'all clear',
    'infected' => 'malware',
    'failed' => 'failed scans',
    'quarantined' => 'quarantined',
    'suspicious' => 'suspicious',
    'scanner_offline' => 'scanner offline',
    'healthy' => 'All clear: :total scans, all clean.',
    'no_activity' => 'No scans ran in this period.',
    'failures_warning' => 'Scans are failing. With fail-closed enabled, every upload is being rejected until the engine recovers.',
    'offline_warning' => 'Scanner offline: :names.',
    'user' => 'user :id',
    'more' => '…and :n more.',
    'view_console' => 'Open the security console',
];
