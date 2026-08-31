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

        'default' => env('CONTENT_SECURITY_MALWARE_DRIVER', 'clamav'),

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

            'null' => [
                'driver' => 'null',
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
        // Filesystem paths are operational detail; hidden unless switched on.
        'expose_paths' => false,
        'brand' => [
            'title' => 'Content Security',
            'back_url' => '/',
            'back_label' => 'Back to app',
        ],
    ],
];
