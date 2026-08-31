<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\SuspiciousContent;

use LaravelPlus\ContentSecurity\Contracts\TextInspector;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * Pattern detection over untrusted text.
 *
 * Read this before relying on it: these are HEURISTICS. They are an audit
 * signal — "someone just posted a UNION SELECT into a job description" — and
 * a tripwire, not a control.
 *
 * SQL injection is prevented by parameterised queries. XSS is prevented by
 * contextual output escaping. Neither is prevented by this class, and a
 * codebase that concatenates user input into SQL is not made safe by adding
 * it. Every pattern here has both false positives (an article *about* SQL
 * injection) and false negatives (any competent obfuscation).
 *
 * Findings are therefore Low/Medium by default: they are worth recording and
 * worth alerting on, and they are not worth blocking a user over on their own.
 */
final class SuspiciousContentScanner implements TextInspector
{
    /**
     * @var list<array{0: string, 1: string, 2: ThreatLevel, 3: string}>
     */
    private const PATTERNS = [
        // Script injection — the shapes that matter when text is later
        // rendered into HTML by something that forgot to escape.
        ['text.script_tag', '/<\s*script[\s>]/i', ThreatLevel::High, 'The text contains a <script> tag.'],
        ['text.iframe_tag', '/<\s*iframe[\s>]/i', ThreatLevel::Medium, 'The text contains an <iframe> tag.'],
        ['text.object_embed', '/<\s*(object|embed|applet)[\s>]/i', ThreatLevel::Medium, 'The text contains an <object>, <embed> or <applet> tag.'],
        ['text.event_handler', '/<[^>]+\s+on[a-z]{3,15}\s*=/i', ThreatLevel::High, 'The text contains inline event handler attributes.'],
        ['text.javascript_uri', '/(?:href|src|action|formaction)\s*=\s*["\']?\s*javascript:/i', ThreatLevel::High, 'The text contains a javascript: URI.'],
        ['text.data_uri_html', '/data:text\/html/i', ThreatLevel::Medium, 'The text contains a data:text/html URI.'],
        ['text.svg_onload', '/<\s*svg[^>]*\son[a-z]+\s*=/i', ThreatLevel::High, 'The text contains an SVG with an event handler.'],

        // Server-side code, which has no business arriving as prose.
        ['text.php_tag', '/<\?(?:php|=)/i', ThreatLevel::High, 'The text contains PHP opening tags.'],
        ['text.template_injection', '/\{\{\s*[\w.]*\s*(?:_self|__class__|constant|system|exec|eval|config)\s*[\w.(]/i', ThreatLevel::Medium, 'The text resembles a server-side template injection payload.'],

        // SQL — signal only. See the class docblock.
        ['text.sql_union', '/\bunion\b[\s\S]{0,40}?\bselect\b/i', ThreatLevel::Low, 'The text resembles a UNION-based SQL injection payload.'],
        ['text.sql_tautology', '/(?:\'|")\s*(?:or|and)\s+(?:\'?\d+\'?\s*=\s*\'?\d+\'?|\'[^\']*\'\s*=\s*\'[^\']*\')/i', ThreatLevel::Low, 'The text resembles a SQL tautology payload.'],
        ['text.sql_comment_terminator', '/(?:\'|");?\s*(?:--|#)\s*$/m', ThreatLevel::Low, 'The text resembles a SQL comment terminator payload.'],
        ['text.sql_stacked_query', '/;\s*(?:drop|delete|update|insert|truncate|alter)\s+(?:table|from|into|database)\b/i', ThreatLevel::Medium, 'The text resembles a stacked SQL statement.'],
        ['text.sql_information_schema', '/\binformation_schema\.(?:tables|columns|schemata)\b/i', ThreatLevel::Low, 'The text references information_schema.'],

        // Command execution and traversal.
        ['text.shell_metacharacters', '/(?:\|\||&&|\$\(|`)\s*(?:cat|curl|wget|nc|bash|sh|python|perl|whoami|id)\b/i', ThreatLevel::Medium, 'The text resembles a shell command injection payload.'],
        ['text.path_traversal', '#(?:\.\./){2,}|(?:\.\.\\\\){2,}#', ThreatLevel::Medium, 'The text contains a directory traversal sequence.'],
        ['text.etc_passwd', '#/etc/(?:passwd|shadow)\b#', ThreatLevel::Medium, 'The text references a sensitive system file.'],

        // Encoding tricks used to slip past everything above.
        ['text.null_byte', '/\x00/', ThreatLevel::High, 'The text contains a null byte.'],
        ['text.bidi_override', '/[\x{202a}-\x{202e}\x{2066}-\x{2069}]/u', ThreatLevel::Medium, 'The text contains bidirectional override characters, which can disguise its true content.'],
    ];

    public function inspect(string $text): Findings
    {
        $threats = [];
        $matched = [];

        foreach (self::PATTERNS as [$name, $pattern, $level, $description]) {
            $count = preg_match_all($pattern, $text);

            if ($count === false || $count === 0) {
                continue;
            }

            $matched[] = $name;
            $threats[] = Threat::make(
                name: $name,
                level: $level,
                source: 'suspicious_content',
                description: $description,
                // Never the matched text itself: the finding would then
                // carry the payload into logs, mail and the admin console.
                metadata: ['occurrences' => $count],
            );
        }

        $controlCharacters = (int) preg_match_all('/[\x01-\x08\x0b\x0c\x0e-\x1f]/', $text);

        if ($controlCharacters > 0) {
            $threats[] = Threat::make(
                name: 'text.control_characters',
                level: ThreatLevel::Low,
                source: 'suspicious_content',
                description: 'The text contains non-printable control characters.',
                metadata: ['occurrences' => $controlCharacters],
            );
        }

        return Findings::of($threats, [
            'length' => mb_strlen($text),
            'patterns_matched' => $matched,
        ]);
    }
}
