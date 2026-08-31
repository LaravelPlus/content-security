<?php

declare(strict_types=1);

use LaravelPlus\ContentSecurity\Contracts\Sanitizer;

function sanitize(string $html): string
{
    return app(Sanitizer::class)->sanitize($html);
}

it('keeps ordinary formatting', function (): void {
    $clean = sanitize('<p>Hello <strong>world</strong>, see <a href="https://jobly.si">this</a>.</p>');

    expect($clean)->toContain('<strong>world</strong>')
        ->and($clean)->toContain('href="https://jobly.si"');
});

it('removes script elements', function (): void {
    expect(sanitize('<p>Hi</p><script>alert(1)</script>'))
        ->not->toContain('<script')
        ->not->toContain('alert(1)');
});

it('removes inline event handlers', function (): void {
    expect(sanitize('<img src="x" onerror="alert(1)">'))
        ->not->toContain('onerror');
});

it('removes javascript: URIs', function (): void {
    expect(sanitize('<a href="javascript:alert(1)">click</a>'))
        ->not->toContain('javascript:');
});

it('removes iframes under the default policy', function (): void {
    expect(sanitize('<iframe src="https://evil.example"></iframe>'))
        ->not->toContain('<iframe');
});

it('strips style attributes', function (): void {
    expect(sanitize('<p style="position:fixed;top:0">x</p>'))
        ->not->toContain('style=');
});

it('forces rel on links', function (): void {
    expect(sanitize('<a href="https://example.com">x</a>'))
        ->toContain('noopener');
});

/**
 * The bypasses that defeat regex-based "sanitizers". Each of these is valid
 * to a browser's parser and invisible to a naive pattern.
 */
it('survives parser-level obfuscation', function (string $payload): void {
    $clean = mb_strtolower(sanitize($payload));

    // The property under test is that nothing *executable* survives: no
    // script element, no javascript: scheme, and no event-handler attribute.
    //
    // Asserting on the substring "onerror" would be wrong. The sanitizer
    // turns `<img src="x onerror="alert(1)">` into
    // `<img src="x%20onerror&#61;" />` — the word survives as encoded text
    // inside an attribute *value*, which is inert. What must not survive is
    // an attribute named on-something.
    expect($clean)->not->toContain('<script')
        ->and($clean)->not->toContain('javascript:')
        ->and($clean)->not->toMatch('/\son[a-z]+\s*=/');
})->with([
    'nested tags' => '<<script>script>alert(1)<</script>/script>',
    'mixed case' => '<ScRiPt>alert(1)</ScRiPt>',
    'null byte' => "<scri\0pt>alert(1)</script>",
    'newline in scheme' => '<a href="java&#10;script:alert(1)">x</a>',
    'entity-encoded scheme' => '<a href="&#106;avascript:alert(1)">x</a>',
    'svg onload' => '<svg onload="alert(1)"></svg>',
    'unclosed attribute' => '<img src="x onerror="alert(1)">',
    'body onload' => '<body onload=alert(1)>',
]);
