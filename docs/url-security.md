# URL security

```php
ContentSecurity::scanUrl($url);
ContentSecurity::isSafeUrl($url);

'website' => ['nullable', app(SafeUrl::class)],
```

## Structural checks (always on)

- **Scheme allowlist.** `javascript:`, `data:`, `file:` and `vbscript:` are
  Critical — each is a direct execution or exfiltration vector.
- **Control characters.** `java\nscript:alert(1)` is how a payload hides from
  a naive scheme check.
- **Embedded credentials.** `https://trusted-bank.si@evil.example/login` — the
  browser ignores everything before the `@`. The phishing classic.
- **Homograph hosts.** Punycode, and mixed-script labels like `аpple.com` with
  a Cyrillic а.
- **Malformed input.**

None of these touch the network.

## SSRF mode

Off by default:

```dotenv
CONTENT_SECURITY_SSRF_PROTECTION=true
CONTENT_SECURITY_URL_RESOLVE_DNS=true
```

Blocks destinations that resolve into loopback, private, link-local and
reserved space — including `169.254.169.254`, the cloud metadata endpoint and
the single most exploited SSRF target.

DNS resolution is opt-in for two reasons. Resolving attacker-supplied
hostnames on every validation is itself a way to make your server do someone
else's bidding. And the answer can change between the check and the request.

## DNS rebinding

**A URL that passes here is safe to store and display. It is not thereby safe
to fetch.**

Validation resolves a hostname now; your HTTP client resolves it again later.
An attacker who controls the DNS can return a public address to the first
lookup and `127.0.0.1` to the second. This is not a flaw in the check — it is
inherent to validating a name and then connecting to it.

If you must fetch user-supplied URLs, pin the address you validated:

```php
$findings = app(UrlInspector::class)->inspect($url);

abort_if($findings->hasAtLeast(ThreatLevel::Medium), 422);

$address = $findings->metadata['resolved'][0] ?? null;

$response = Http::withOptions([
    // Connect to the address that was checked, not to whatever DNS says now.
    'curl' => [CURLOPT_RESOLVE => ["{$host}:443:{$address}"]],
])->get($url);
```

Also: disable redirect following, or re-check every hop. A 302 to
`http://169.254.169.254/` walks straight through a check that only looked at
the original URL.

## Allow and block lists

```php
'urls' => [
    'allowed_hosts' => ['github.com', 'linkedin.com'],
    'blocked_hosts' => ['bit.ly'],
],
```

Subdomains match: `github.com` allows `gist.github.com`.

## Messages

URLs are the one place a specific message is safe and useful — the user typed
it and can see it, so naming the scheme reveals nothing new:

> Only http:// and https:// addresses are accepted.
