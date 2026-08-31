<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\Checks;

use LaravelPlus\ContentSecurity\Contracts\TextCheck;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use LaravelPlus\ContentSecurity\Text\Url\UrlScanner;

/**
 * Pulls URLs out of free text and runs each through the URL scanner.
 */
final class UrlsCheck implements TextCheck
{
    /** Bounded so a wall of links cannot turn one scan into thousands. */
    private const MAX_URLS = 50;

    public function __construct(private readonly UrlScanner $scanner) {}

    public function key(): string
    {
        return 'urls';
    }

    public function label(): string
    {
        return 'URLs';
    }

    public function check(string $text, TextPolicy $policy, ScanContext $context): CheckResult
    {
        $urls = $this->extract($text);

        if ($urls === []) {
            return CheckResult::passed($this->key(), ['urls' => 0]);
        }

        $threats = [];
        $inspected = 0;

        foreach ($urls as $url) {
            if ($inspected >= self::MAX_URLS) {
                break;
            }

            $inspected++;

            foreach ($this->scanner->inspect($url)['threats'] as $threat) {
                $threats[] = Threat::make(
                    name: $threat->name,
                    level: $threat->level,
                    source: $this->key(),
                    description: $threat->description,
                    metadata: [...$threat->metadata, 'url' => $this->redact($url)],
                );
            }
        }

        $metadata = [
            'urls' => count($urls),
            'inspected' => $inspected,
            'truncated' => count($urls) > self::MAX_URLS,
        ];

        if ($threats === []) {
            return CheckResult::passed($this->key(), $metadata);
        }

        $blocking = array_filter(
            $threats,
            static fn (Threat $threat): bool => $threat->isAtLeast(ThreatLevel::High),
        );

        return $blocking !== []
            ? CheckResult::infected($this->key(), array_values($threats), $metadata)
            : CheckResult::suspicious($this->key(), array_values($threats), $metadata);
    }

    /**
     * @return list<string>
     */
    private function extract(string $text): array
    {
        // Schemes first, so javascript:/data: payloads are caught rather
        // than skipped by an http-only pattern.
        preg_match_all('#\b[a-z][a-z0-9+.-]{1,20}:(?://)?[^\s<>"\']{1,2000}#i', $text, $matches);

        /** @var list<string> $urls */
        $urls = array_values(array_unique($matches[0]));

        return $urls;
    }

    /** Keeps scheme and host; drops the path, which may carry a token. */
    private function redact(string $url): string
    {
        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'])) {
            return '[unparseable]';
        }

        return isset($parts['host'])
            ? $parts['scheme'].'://'.$parts['host']
            : $parts['scheme'].':…';
    }
}
