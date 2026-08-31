<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\Url;

use LaravelPlus\ContentSecurity\Contracts\UrlInspector;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * Structural URL validation, plus an optional SSRF-aware mode.
 *
 * The default mode never touches the network: it reads the URL. DNS
 * resolution is opt-in because resolving attacker-supplied hostnames on
 * every validation is itself a way to make your server do someone's
 * bidding, and because DNS answers can change between the check and the
 * request (the rebinding problem — see the README).
 */
final class UrlScanner implements UrlInspector
{
    /**
     * @param  list<string>  $allowedSchemes
     * @param  list<string>  $allowedHosts
     * @param  list<string>  $blockedHosts
     */
    public function __construct(
        private readonly array $allowedSchemes = ['http', 'https'],
        private readonly bool $blockCredentials = true,
        private readonly bool $blockPunycode = true,
        private readonly bool $ssrfProtection = false,
        private readonly bool $resolveDns = false,
        private readonly array $allowedHosts = [],
        private readonly array $blockedHosts = [],
    ) {}

    public static function fromConfig(): self
    {
        /** @var list<string> $schemes */
        $schemes = (array) config('content-security.urls.allowed_schemes', ['http', 'https']);
        /** @var list<string> $allowedHosts */
        $allowedHosts = (array) config('content-security.urls.allowed_hosts', []);
        /** @var list<string> $blockedHosts */
        $blockedHosts = (array) config('content-security.urls.blocked_hosts', []);

        return new self(
            allowedSchemes: $schemes,
            blockCredentials: (bool) config('content-security.urls.block_credentials', true),
            blockPunycode: (bool) config('content-security.urls.block_punycode', true),
            ssrfProtection: (bool) config('content-security.urls.ssrf_protection', false),
            resolveDns: (bool) config('content-security.urls.resolve_dns', false),
            allowedHosts: $allowedHosts,
            blockedHosts: $blockedHosts,
        );
    }

    public function inspect(string $url): Findings
    {
        $url = trim($url);
        $metadata = ['url_length' => mb_strlen($url)];

        if ($url === '') {
            return Findings::of($this->threat('url.empty', ThreatLevel::Low, 'The URL is empty.'), $metadata);
        }

        // Control characters and whitespace inside a URL are how a payload
        // hides from a naive scheme check: "java\nscript:alert(1)".
        if (preg_match('/[\x00-\x1f\x7f]/', $url) === 1) {
            return Findings::of($this->threat(
                'url.control_characters',
                ThreatLevel::High,
                'The URL contains control characters.',
            ), $metadata);
        }

        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'])) {
            return Findings::of($this->threat(
                'url.malformed',
                ThreatLevel::Medium,
                'The URL is malformed or has no scheme.',
            ), $metadata);
        }

        $scheme = mb_strtolower($parts['scheme']);
        $host = isset($parts['host']) ? mb_strtolower($parts['host']) : null;

        $metadata['scheme'] = $scheme;
        $metadata['host'] = $host;

        $threats = [];

        if (! in_array($scheme, array_map(mb_strtolower(...), $this->allowedSchemes), true)) {
            $threats[] = $this->threat(
                'url.scheme_not_allowed',
                // javascript:, data: and file: are not merely disallowed —
                // each is a direct execution or exfiltration vector.
                in_array($scheme, ['javascript', 'data', 'file', 'vbscript'], true)
                    ? ThreatLevel::Critical
                    : ThreatLevel::High,
                sprintf('The scheme %s: is not allowed.', $scheme),
                ['scheme' => $scheme],
            );

            return Findings::of($threats, $metadata);
        }

        if ($this->blockCredentials && (isset($parts['user']) || isset($parts['pass']))) {
            $threats[] = $this->threat(
                'url.embedded_credentials',
                ThreatLevel::High,
                'The URL embeds credentials, a common phishing disguise (https://trusted.com@evil.com).',
            );
        }

        if ($host === null || $host === '') {
            $threats[] = $this->threat('url.no_host', ThreatLevel::Medium, 'The URL has no host.');

            return Findings::of($threats, $metadata);
        }

        if ($this->blockPunycode && $this->looksHomographic($host)) {
            $threats[] = $this->threat(
                'url.suspicious_unicode_host',
                ThreatLevel::Medium,
                sprintf('The host [%s] uses internationalised characters that can imitate another domain.', $host),
                ['host' => $host],
            );
        }

        if ($this->blockedHosts !== [] && $this->matchesHostList($host, $this->blockedHosts)) {
            $threats[] = $this->threat(
                'url.blocked_host',
                ThreatLevel::High,
                sprintf('The host [%s] is on the block list.', $host),
                ['host' => $host],
            );
        }

        if ($this->allowedHosts !== [] && ! $this->matchesHostList($host, $this->allowedHosts)) {
            $threats[] = $this->threat(
                'url.host_not_allowed',
                ThreatLevel::High,
                sprintf('The host [%s] is not on the allow list.', $host),
                ['host' => $host],
            );
        }

        if ($this->ssrfProtection) {
            foreach ($this->inspectForSsrf($host, $metadata) as $threat) {
                $threats[] = $threat;
            }
        }

        return Findings::of($threats, $metadata);
    }

    public function isSafe(string $url): bool
    {
        foreach ($this->inspect($url)->threats as $threat) {
            if ($threat->isAtLeast(ThreatLevel::Medium)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param  array<string, mixed>  $metadata
     * @return list<Threat>
     */
    private function inspectForSsrf(string $host, array &$metadata): array
    {
        $threats = [];

        if (in_array($host, ['localhost', 'localhost.localdomain', '[::1]'], true)) {
            $metadata['ssrf'] = 'loopback-hostname';

            return [$this->threat(
                'url.internal_destination',
                ThreatLevel::Critical,
                'The URL points at the local machine.',
                ['host' => $host],
            )];
        }

        $literal = trim($host, '[]');
        $addresses = [];

        if (filter_var($literal, FILTER_VALIDATE_IP) !== false) {
            $addresses = [$literal];
        } elseif ($this->resolveDns) {
            $records = @dns_get_record($host, DNS_A | DNS_AAAA);

            if (is_array($records)) {
                foreach ($records as $record) {
                    $address = $record['ip'] ?? $record['ipv6'] ?? null;

                    if (is_string($address)) {
                        $addresses[] = $address;
                    }
                }
            }

            $metadata['resolved'] = $addresses;
        }

        foreach ($addresses as $address) {
            if ($this->isPrivateAddress($address)) {
                $threats[] = $this->threat(
                    'url.internal_destination',
                    ThreatLevel::Critical,
                    sprintf('The URL resolves to the internal address %s.', $address),
                    ['host' => $host, 'address' => $address],
                );
            }
        }

        if ($addresses !== [] && $threats === []) {
            // Resolving now says nothing about the address the HTTP client
            // will connect to later. Callers that must be safe should pin
            // the address they validated — see docs/url-security.md.
            $metadata['ssrf'] = 'resolved-public';
        }

        return $threats;
    }

    private function isPrivateAddress(string $address): bool
    {
        // FILTER_FLAG_NO_PRIV_RANGE covers 10/8, 172.16/12, 192.168/16 and
        // fc00::/7; NO_RES_RANGE covers loopback, link-local (including the
        // cloud metadata address 169.254.169.254) and the reserved blocks.
        return filter_var(
            $address,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) === false;
    }

    /** @param list<string> $list */
    private function matchesHostList(string $host, array $list): bool
    {
        foreach ($list as $candidate) {
            $candidate = mb_strtolower(ltrim($candidate, '.'));

            if ($host === $candidate || str_ends_with($host, '.'.$candidate)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Mixing scripts inside one label — "аpple.com" with a Cyrillic а — is
     * the homograph attack. An all-ASCII or single-script host is fine.
     */
    private function looksHomographic(string $host): bool
    {
        if (str_starts_with($host, 'xn--') || str_contains($host, '.xn--')) {
            return true;
        }

        if (preg_match('/^[\x20-\x7e]*$/', $host) === 1) {
            return false;
        }

        return preg_match('/[a-z]/i', $host) === 1
            && preg_match('/[^\x00-\x7f]/', $host) === 1;
    }

    /**
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    private function threat(string $name, ThreatLevel $level, string $description, array $metadata = []): Threat
    {
        return Threat::make($name, $level, 'url', $description, $metadata);
    }
}
