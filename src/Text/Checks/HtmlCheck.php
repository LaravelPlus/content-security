<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\Checks;

use LaravelPlus\ContentSecurity\Contracts\Sanitizer;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * Runs the input through the sanitizer and reports what had to be removed.
 * The verdict is a *difference*, which is the only honest way to answer "was
 * this HTML safe?" — a parser's opinion, not a pattern's.
 *
 * The sanitized output travels back in the check metadata, so a caller that
 * wants the clean version does not sanitize twice.
 */
final class HtmlCheck extends AbstractTextCheck
{
    /** Below this, the difference is entity normalisation, not a removal. */
    private const NOISE_THRESHOLD = 8;

    public function __construct(private readonly Sanitizer $sanitizer) {}

    public function key(): string
    {
        return 'html';
    }

    public function label(): string
    {
        return 'HTML sanitization';
    }

    protected function inspect(string $text, TextPolicy $policy, ScanContext $context): Findings
    {
        $sanitized = $this->sanitizer->sanitize($text);

        $original = mb_strlen($text);
        $cleanLength = mb_strlen($sanitized);
        $removed = max(0, $original - $cleanLength);

        $metadata = [
            'original_length' => $original,
            'sanitized_length' => $cleanLength,
            'removed_characters' => $removed,
            'sanitized' => $sanitized,
        ];

        if ($sanitized === $text || $removed <= self::NOISE_THRESHOLD) {
            return Findings::none($metadata);
        }

        return Findings::of(Threat::make(
            name: 'html.unsafe_markup_removed',
            // Suspicious, not infected: the sanitizer already neutralised
            // it. This tells an operator someone is probing, and lets the
            // application keep the cleaned text if it wants to.
            level: ThreatLevel::Medium,
            source: $this->key(),
            description: sprintf('The sanitizer removed %d characters of disallowed markup.', $removed),
            metadata: ['removed_characters' => $removed],
        ), $metadata);
    }
}
