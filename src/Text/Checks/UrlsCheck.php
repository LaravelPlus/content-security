<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\Checks;

use LaravelPlus\ContentSecurity\Contracts\UrlInspector;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;

/**
 * Pulls URLs out of free text and runs each through the URL inspector.
 */
final class UrlsCheck extends AbstractTextCheck
{
    /** Bounded, so a wall of links cannot turn one scan into thousands. */
    private const MAX_URLS = 50;

    public function __construct(private readonly UrlInspector $inspector) {}

    public function key(): string
    {
        return 'urls';
    }

    public function label(): string
    {
        return 'URLs';
    }

    protected function inspect(string $text, TextPolicy $policy, ScanContext $context): Findings
    {
        $urls = $this->extract($text);

        if ($urls === []) {
            return Findings::none(['urls' => 0]);
        }

        $threats = [];
        $inspected = 0;

        foreach ($urls as $url) {
            if ($inspected >= self::MAX_URLS) {
                break;
            }

            $inspected++;

            foreach ($this->inspector->inspect($url)->threats as $threat) {
                $threats[] = Threat::make(
                    name: $threat->name,
                    level: $threat->level,
                    source: $this->key(),
                    description: $threat->description,
                    metadata: [...$threat->metadata, 'url' => $this->redact($url)],
                );
            }
        }

        return Findings::of($threats, [
            'urls' => count($urls),
            'inspected' => $inspected,
            'truncated' => count($urls) > self::MAX_URLS,
        ]);
    }

    /**
     * @return list<string>
     */
    private function extract(string $text): array
    {
        // Any scheme, not just http(s): a pattern that only matches http
        // would skip the javascript: and data: payloads that matter most.
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
