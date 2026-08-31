# Text and HTML

Read this page before relying on anything in it.

## What text scanning is not

**It does not prevent SQL injection.** Parameterised queries do — Eloquent,
the query builder, or PDO bindings. The suspicious-content scanner recognises
some payload *shapes*, which is useful as an alerting signal and useless as a
control. A codebase that concatenates user input into SQL is not made safe by
installing this package.

**It does not prevent XSS.** Contextual output escaping does. Blade's `{{ }}`,
Vue's text interpolation, and not calling `v-html` on untrusted input. What
this package adds is a real sanitizer for markup you have *decided* to accept
and re-render.

Every pattern here has false positives (an article *about* SQL injection) and
false negatives (any competent obfuscation). Findings are Low and Medium by
default: worth recording, worth alerting on, and not worth blocking a user
over on their own.

So what is it for?

- A tripwire. A `<script>` tag arriving in a field that should hold a job
  title is a fact worth knowing, even if your escaping already handles it.
- An audit trail. "This account posted forty SQLi payloads last night" is a
  useful sentence.
- Defence in depth against the template that forgets to escape. Not a
  substitute for fixing it.

## HTML sanitization

This one *is* a control.

```php
$clean = ContentSecurity::sanitizeHtml($html);
```

Backed by `symfony/html-sanitizer`, which parses the document with a real
HTML5 parser and rebuilds it from an allowlist.

### Why never a regex

HTML is not a regular language. `<<script>script>`, `<ScRiPt>`, entity-encoded
schemes, unclosed attributes, null bytes mid-tag and mXSS all defeat pattern
matching, and every "sanitize with a regex" library in history has been
bypassed. Parse it, or do not claim to have sanitized it.

The test suite exercises eight of these bypasses. Adding more is welcome.

### Configuration

```php
'html' => [
    'allowed_tags' => ['p', 'strong', 'em', 'a', 'ul', 'ol', 'li', /* … */],
    'allowed_attributes' => [
        'a' => ['href', 'title', 'rel', 'target'],
        '*' => ['class'],
    ],
    'allowed_schemes' => ['http', 'https', 'mailto'],
    'allowed_iframe_hosts' => [],          // empty = iframes dropped
    'force_link_rel' => 'noopener noreferrer nofollow',
    'allow_inline_styles' => false,
    'max_input_length' => 1_000_000,
],
```

Defaults are conservative. Widen them deliberately.

`rel="noopener"` is forced on every link: without it, `window.opener` hands
the destination page control of the tab it came from. Inline styles are
stripped because the `style` attribute is its own XSS surface —
`url(javascript:…)`, `expression()`, and CSS that repositions an element over
a control the user meant to click.

### Sanitize or reject?

Both are available. For user-facing forms, sanitizing is usually kinder:

```php
$post->body = ContentSecurity::sanitizeHtml($request->string('body'));
```

Rejecting tells someone pasting from Word that their input is "unsafe";
sanitizing quietly removes the `<o:p>` tags.

Reach for the rule when unexpected markup is itself the signal you want:

```php
'description' => ['required', new SafeHtml()],
```

The rule hands you the cleaned version either way:

```php
$rule = new SafeHtml();
$request->validate(['description' => ['required', $rule]]);

$clean = $rule->sanitized();
```

## The text pipeline

```
length → html → suspicious → urls
```

The sanitizer runs **before** pattern matching, deliberately. Suspicious
content reports `<script>` as a high finding, which ends the run — with it
first, the sanitizer never ran on precisely the input that needed sanitizing,
and `SafeHtml::sanitized()` came back null on every document that actually
contained markup to strip.

`length` cannot be switched off: it is what stops the pattern checks from
being handed an unbounded string.

## Policies

```php
'text' => [
    'policies' => [
        'default' => ['max_length' => 200_000, 'checks' => ['suspicious' => true, 'html' => false, 'urls' => true]],
        'rich'    => ['max_length' => 500_000, 'checks' => ['suspicious' => true, 'html' => true,  'urls' => true]],
    ],
],
```

`scanHtml()` uses `rich` by default.

## Privacy

Scanned text is never stored. The audit row keeps a SHA-256 and a length.
Threat metadata records how many times a pattern matched, never what matched —
otherwise the finding carries the payload into logs, mail and the console.

Opt in to short samples if you need them:

```php
'persistence' => [
    'store_text_samples' => true,
    'text_sample_length' => 200,
],
```

Think about your retention and privacy obligations before you do.

## Scanning whole requests

Not built in, and the seam is there for it. Register a check and apply it
across request input in middleware:

```php
ContentSecurity::addTextCheck(MyRequestPayloadCheck::class);
```

Treat it as monitoring, not as a WAF — see the top of this page for why.
