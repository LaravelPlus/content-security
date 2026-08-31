# File scanning

## The pipeline

```
size → extension → MIME → magic bytes → archive → image → PDF → malware
```

Cheapest first. Everything before `malware` is a handful of syscalls; the
malware step is a network round trip and a full stream of the file. Rejecting
a 900 MB `.php` upload on its extension costs microseconds, and the daemon
never sees it.

Two rules govern the run:

- A check that throws becomes a **failed** result — never a pass, and never an
  exception that reaches your controller or kills a queue worker.
- A definite finding (infected) or, under `fail_closed`, a failed check ends
  the run. The verdict cannot become clean, so further work would be spent on
  a decided outcome.

Checks the policy switched off are still recorded, as *skipped*. A disabled
malware scan must never look identical to a passing one.

## What each check does

### size

First, so nothing else reads an oversized file. Empty files are flagged (low).

### extension

Allowlist, not blocklist — the only way to stay ahead of formats nobody has
thought of yet. Checks **every** segment of the name, not just the last:
`invoice.pdf.php` and `avatar.php.jpg` both carry an executable extension, and
a web server misconfigured to match `\.php` anywhere in the path will run both.

`forbidden_extensions` is enforced on top of any allowlist and cannot be
widened from the console or the database.

### mime

Compares three claims: the extension, the browser's `Content-Type`, and what
libmagic reads out of the bytes. Only the last is evidence. A mismatch between
detected type and extension is a **high** finding — that is deception, not
preference. A mismatch with the browser's declared type is informational;
browsers get it wrong unprompted and the header is uploader-controlled anyway.

If detection fails entirely, the check **fails** rather than passing. "We could
not tell what this is" must never read as a pass.

### magic_bytes

Recognises executable and script *formats* regardless of name or MIME: PE/DOS,
ELF, Mach-O, Java class, shebang scripts, PHP tags. It also looks for `<?php`
anywhere in the header — the polyglot upload that is a valid image to a viewer
and a webshell to an interpreter.

This is not malware detection. It recognises formats, not payloads.

### archive

Reads the table of contents. Nothing is ever extracted to a public path.
Detects compression bombs, path traversal (Zip Slip), null bytes in entry
names, executable entries, and breaches of the file-count, uncompressed-size
and depth limits. Nested archives are inspected from a bounded temporary copy
that is deleted immediately.

Each breached limit is reported once — a limit crossed on entry 12 of 40,000
must not produce 39,988 identical findings.

### image

Proves an image is an image by decoding it. Detects pixel bombs (tiny file,
enormous canvas — whatever resizes it later allocates `width × height × 4`
bytes) and trailing data after the format's end marker.

SVG takes a different path entirely: it is XML, not pixels, and the one image
type a browser will execute. Script elements, `javascript:` URIs,
`<foreignObject>`, entity declarations and inline event handlers are all
flagged.

Optional re-encoding rewrites the file from decoded pixels, which strips
metadata and anything appended after the last marker.

### pdf

Reports what a PDF *can do*, not whether it is malicious. A PDF that parses is
not a safe PDF — JavaScript, embedded files and launch actions are all legal,
and all of them are how most PDF attacks arrive. Findings are capabilities;
you decide what to make of a document that wants to run script on open.

Read as a bounded byte stream. Object streams can hide these markers behind
compression — a known limit of any non-rendering inspector, and what the
malware engine is for.

### malware

The signature engine. An engine that cannot answer produces a **failed** check.
That is the whole of fail-closed.

## Policies

```php
FilePolicy::default();
FilePolicy::images();
FilePolicy::documents();
FilePolicy::named('avatars');
FilePolicy::custom(['pdf', 'docx'], maxSize: 5 * 1024 * 1024);
```

```php
ContentSecurity::scanFile($file, 'images');
new SafeFile('images');
```

See [policies.md](policies.md).

## Reading the result

```php
$result = ContentSecurity::scanFile($file);

$result->isClean();            // the only thing that grants passage
$result->isThreat();           // a definite or probable finding
$result->failed();             // a scanner could not answer
$result->status();             // ScanStatus enum
$result->threats();            // list<Threat>
$result->checks();             // per-check outcomes, timings, metadata
$result->highestThreatLevel(); // ThreatLevel|null
$result->duration();           // milliseconds
$result->scanId();             // ULID — your join key across systems
```

`isClean()` is the question to ask. Everything else is for logging, the
console, and deciding what to tell an operator.

### Status, and what it means

| Status | Meaning |
| --- | --- |
| `clean` | Every enabled check passed. |
| `suspicious` | A policy rejection or a lower-confidence finding. Not clean. |
| `infected` | Dangerous content: malware, executable format, traversal. |
| `failed` | A check could not complete. **Not clean.** |
| `quarantined` | Rejected, and the file was kept for review. |
| `pending` / `scanning` | Queued work in flight. |

Policy rejections (too large, extension not allowed) read as *suspicious*
rather than *infected*, so the console distinguishes "we do not accept this"
from "this is dangerous". Both fail `isClean()`.

## Memory

Nothing loads a file into memory. Checksums, magic bytes, PDF markers, image
trailing-data scans and the ClamAV upload are all streamed, so a 500 MB upload
costs a buffer rather than 500 MB of PHP heap. Checksums are SHA-256; MD5 is
not a security checksum and is not offered.
