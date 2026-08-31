<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Master switch
    |--------------------------------------------------------------------------
    | Disabling the package stops scanning entirely. Validation rules then
    | pass everything through, so only disable it in environments where no
    | untrusted content is accepted.
    */

    'enabled' => (bool) env('CONTENT_SECURITY_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Fail closed
    |--------------------------------------------------------------------------
    | When a check cannot complete (scanner down, timeout, unreadable file)
    | the scan is reported as FAILED and is NOT clean. Turning this off makes
    | an unavailable malware scanner silently accept every upload.
    */

    'fail_closed' => (bool) env('CONTENT_SECURITY_FAIL_CLOSED', true),

    /*
    |--------------------------------------------------------------------------
    | File policies
    |--------------------------------------------------------------------------
    | `default` is used whenever a rule or API call does not name a policy.
    | Every other key is addressable: new SafeFile('avatars').
    */

    'files' => [

        'default_policy' => 'default',

        'policies' => [

            'default' => [
                'label' => 'Default Upload Policy',
                'max_size' => 25 * 1024 * 1024,
                'extensions' => [
                    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
                    'odt', 'ods', 'csv', 'txt', 'rtf',
                    'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg',
                    'zip',
                ],
                'mime_types' => [],
                'checks' => [
                    'size' => true,
                    'extension' => true,
                    'mime' => true,
                    'magic_bytes' => true,
                    'archive' => true,
                    'image' => true,
                    'pdf' => true,
                    'malware' => true,
                ],
                'on_threat' => 'quarantine',
            ],

            'images' => [
                'label' => 'Avatar / Image Policy',
                'max_size' => 8 * 1024 * 1024,
                'extensions' => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'avif'],
                'mime_types' => ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif'],
                'checks' => [
                    'size' => true,
                    'extension' => true,
                    'mime' => true,
                    'magic_bytes' => true,
                    'archive' => false,
                    'image' => true,
                    'pdf' => false,
                    'malware' => true,
                ],
                'on_threat' => 'reject',
            ],

            'documents' => [
                'label' => 'Document Policy',
                'max_size' => 50 * 1024 * 1024,
                'extensions' => ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'csv', 'txt', 'rtf'],
                'mime_types' => [],
                'checks' => [
                    'size' => true,
                    'extension' => true,
                    'mime' => true,
                    'magic_bytes' => true,
                    'archive' => true,
                    'image' => false,
                    'pdf' => true,
                    'malware' => true,
                ],
                'on_threat' => 'quarantine',
            ],
        ],

        /*
        | Extensions that are never accepted, whatever a policy allows. These
        | are formats a misconfigured web server may execute. The allowlist is
        | the real control; this is the seatbelt behind it.
        */
        /*
        | A hard ceiling on max_size that a runtime override cannot exceed.
        | The per-policy max_size is the working limit; this is the bound on
        | what anyone editing a policy from the console can raise it to.
        */
        'max_size_ceiling' => 512 * 1024 * 1024,

        'forbidden_extensions' => [
            'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phps', 'pht', 'phtml', 'phar',
            'cgi', 'pl', 'py', 'rb', 'sh', 'bash', 'zsh',
            'exe', 'dll', 'com', 'bat', 'cmd', 'scr', 'msi', 'vbs', 'vbe', 'js', 'jse',
            'jar', 'ws', 'wsf', 'ps1', 'psm1', 'hta', 'lnk', 'so', 'dylib',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Text policies
    |--------------------------------------------------------------------------
    */

    'text' => [

        'default_policy' => 'default',

        'policies' => [

            'default' => [
                'label' => 'Plain Text Policy',
                'max_length' => 200_000,
                'checks' => [
                    'suspicious' => true,
                    'html' => false,
                    'urls' => true,
                ],
            ],

            'rich' => [
                'label' => 'Rich Text Policy',
                'max_length' => 500_000,
                'checks' => [
                    'suspicious' => true,
                    'html' => true,
                    'urls' => true,
                ],
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | HTML sanitization
    |--------------------------------------------------------------------------
    | Backed by symfony/html-sanitizer (a real HTML5 parser). Anything not
    | listed is dropped. Conservative by design — widen it deliberately.
    */

    'html' => [

        'allowed_tags' => [
            'p', 'br', 'hr', 'span', 'div',
            'strong', 'b', 'em', 'i', 'u', 's', 'sub', 'sup', 'mark',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
            'a', 'img',
            'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption',
        ],

        'allowed_attributes' => [
            'a' => ['href', 'title', 'rel', 'target'],
            'img' => ['src', 'alt', 'title', 'width', 'height'],
            'th' => ['colspan', 'rowspan', 'scope'],
            'td' => ['colspan', 'rowspan'],
            '*' => ['class'],
        ],

        'allowed_schemes' => ['http', 'https', 'mailto'],

        'allow_relative_links' => true,
        'allow_relative_medias' => true,

        // Dropped outright: no <iframe> in default policy.
        'allowed_iframe_hosts' => [],

        // Rewritten onto every link that leaves the site.
        'force_link_rel' => 'noopener noreferrer nofollow',
        'force_link_target' => null,

        // Inline style attributes are never allowed (CSS is an XSS surface).
        'allow_inline_styles' => false,

        'max_input_length' => 1_000_000,
    ],

    /*
    |--------------------------------------------------------------------------
    | URL security
    |--------------------------------------------------------------------------
    */

    'urls' => [
        'allowed_schemes' => ['http', 'https'],
        'block_credentials' => true,
        'block_punycode' => true,
        // SSRF mode rejects hosts that resolve to loopback/private/link-local
        // space. It performs a DNS lookup, so it is off by default.
        'ssrf_protection' => (bool) env('CONTENT_SECURITY_SSRF_PROTECTION', false),
        'resolve_dns' => (bool) env('CONTENT_SECURITY_URL_RESOLVE_DNS', false),
        'allowed_hosts' => [],
        'blocked_hosts' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Malware scanning
    |--------------------------------------------------------------------------
    | Drivers are resolved through a manager. Register your own with
    | ContentSecurity::extend('name', fn ($app) => new MyScanner(...)).
    */

    'malware' => [

        /*
        | `?: 'none'` is load-bearing. Laravel's env() casts the STRING "null"
        | to PHP null, so CONTENT_SECURITY_MALWARE_DRIVER=null — the obvious
        | way to ask for no engine — resolved to null, not to the driver
        | named "null". The manager then had no driver at all and every scan
        | failed closed, which on an upload endpoint means every upload
        | rejected. The driver is therefore called `none`; `null` still
        | works as an alias for anyone who already wrote it.
        */
        'default' => env('CONTENT_SECURITY_MALWARE_DRIVER', 'clamav') ?: 'none',

        'drivers' => [

            'clamav' => [
                'driver' => 'clamav',
                'connection' => env('CONTENT_SECURITY_CLAMAV_CONNECTION', 'unix'),
                'unix_socket' => env('CONTENT_SECURITY_CLAMAV_SOCKET', '/var/run/clamav/clamd.ctl'),
                'host' => env('CONTENT_SECURITY_CLAMAV_HOST', '127.0.0.1'),
                'port' => (int) env('CONTENT_SECURITY_CLAMAV_PORT', 3310),
                'timeout' => (int) env('CONTENT_SECURITY_CLAMAV_TIMEOUT', 30),
                // clamd refuses INSTREAM payloads above StreamMaxLength.
                'chunk_size' => 65_536,
                'max_stream_size' => (int) env('CONTENT_SECURITY_CLAMAV_MAX_STREAM', 100 * 1024 * 1024),
                // Falls back to the clamscan binary when clamd is unreachable.
                'cli_fallback' => (bool) env('CONTENT_SECURITY_CLAMAV_CLI_FALLBACK', false),
                'cli_binary' => env('CONTENT_SECURITY_CLAMAV_BINARY', 'clamscan'),
            ],

            'none' => [
                'driver' => 'none',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Archive inspection
    |--------------------------------------------------------------------------
    */

    'archives' => [
        'max_depth' => 3,
        'max_files' => 500,
        'max_uncompressed_size' => 500 * 1024 * 1024,
        'max_compression_ratio' => 100,
        'forbidden_entry_extensions' => null, // null = reuse files.forbidden_extensions
    ],

    /*
    |--------------------------------------------------------------------------
    | Image inspection
    |--------------------------------------------------------------------------
    */

    'images' => [
        'strip_metadata' => true,
        'reencode' => false,
        'max_pixels' => 50_000_000,
        // SVG is XML and can carry script. Sanitized as HTML when allowed.
        'sanitize_svg' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | PDF inspection
    |--------------------------------------------------------------------------
    */

    'pdf' => [
        'block_javascript' => true,
        'block_embedded_files' => true,
        'block_launch_actions' => true,
        'block_encrypted' => true,
        'max_objects' => 50_000,
        // Bytes read while looking for markers. PDFs stream; this bounds work.
        'scan_bytes' => 20 * 1024 * 1024,
    ],

    /*
    |--------------------------------------------------------------------------
    | Storage / quarantine
    |--------------------------------------------------------------------------
    */

    'storage' => [
        'quarantine_disk' => env('CONTENT_SECURITY_QUARANTINE_DISK', 'local'),
        'quarantine_path' => 'content-security/quarantine',
        'retention_days' => 30,
    ],

    /*
    |--------------------------------------------------------------------------
    | Queue
    |--------------------------------------------------------------------------
    */

    'queue' => [
        'connection' => env('CONTENT_SECURITY_QUEUE_CONNECTION'),
        'queue' => env('CONTENT_SECURITY_QUEUE', 'default'),
        'tries' => 3,
        'timeout' => 300,
        'backoff' => [10, 60, 300],
    ],

    /*
    |--------------------------------------------------------------------------
    | Persistence
    |--------------------------------------------------------------------------
    */

    'persistence' => [
        'enabled' => true,
        'connection' => null,
        // Text scans record a SHA-256 of the input and its length only.
        // Never the text itself unless you opt in below.
        'store_text_samples' => false,
        'text_sample_length' => 200,
        'prune_after_days' => 180,
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    */

    'logging' => [
        'enabled' => true,
        'channel' => env('CONTENT_SECURITY_LOG_CHANNEL'),
        'level' => 'info',
        'threat_level' => 'warning',
    ],

    /*
    |--------------------------------------------------------------------------
    | Mail reports
    |--------------------------------------------------------------------------
    | A daily digest and a weekly roll-up. Both are scheduled automatically
    | once recipients are set; with none configured the commands exit
    | quietly, so the schedule is safe to leave registered.
    |
    | The daily mail is sent only when there is something to say (findings,
    | scan failures, or an offline engine). The weekly one always goes out,
    | so a silent week is confirmed rather than merely assumed.
    */

    'reports' => [

        // A comma-separated list, or an array.
        'recipients' => env('CONTENT_SECURITY_REPORT_TO'),

        'timezone' => env('CONTENT_SECURITY_REPORT_TIMEZONE', env('APP_TIMEZONE', 'UTC')),

        'daily' => [
            'enabled' => (bool) env('CONTENT_SECURITY_REPORT_DAILY', true),
            'at' => env('CONTENT_SECURITY_REPORT_DAILY_AT', '07:30'),
        ],

        'weekly' => [
            'enabled' => (bool) env('CONTENT_SECURITY_REPORT_WEEKLY', true),
            'day' => env('CONTENT_SECURITY_REPORT_WEEKLY_DAY', 'monday'),
            'at' => env('CONTENT_SECURITY_REPORT_WEEKLY_AT', '08:00'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Maintenance schedule
    |--------------------------------------------------------------------------
    */

    'schedule' => [
        'cleanup_quarantine' => (bool) env('CONTENT_SECURITY_SCHEDULE_CLEANUP', true),
        'cleanup_at' => '03:30',
    ],

    /*
    |--------------------------------------------------------------------------
    | Admin console
    |--------------------------------------------------------------------------
    | Authorization is the host application's decision. Register a callback
    | with ContentSecurity::auth(fn ($user) => $user->isAdmin()) or point
    | `gate` at one of your own Gate abilities.
    */

    'admin' => [
        'enabled' => (bool) env('CONTENT_SECURITY_ADMIN_ENABLED', true),
        'prefix' => env('CONTENT_SECURITY_ADMIN_PREFIX', 'admin/content-security'),
        'route_name' => 'admin.content-security.',
        'middleware' => ['web', 'auth'],
        'gate' => null,
        'per_page' => 25,

        /*
        | Runtime policy editing from the console.
        |
        | Config stays the baseline either way; with this on, the database
        | may hold per-policy overrides on top of it, each change audited
        | via the PolicyChanged event. `forbidden_extensions` and the
        | max_size ceiling above are never overridable.
        |
        | Turn it off for installations that want their security policy to
        | be reviewable in a diff and nowhere else.
        */
        'manage_policies' => (bool) env('CONTENT_SECURITY_MANAGE_POLICIES', true),
        // Filesystem paths are operational detail; hidden unless switched on.
        'expose_paths' => false,
        'brand' => [
            'title' => 'Content Security',
            'back_url' => '/',
            'back_label' => 'Back to app',
        ],
    ],
];
