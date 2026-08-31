# Threat model

## What this layer covers

| Threat | Covered by |
| --- | --- |
| Webshell upload (`.php`, `.phar`, double extension) | extension allowlist + forbidden list + magic bytes |
| Executable disguised as an image or document | MIME/extension comparison + magic bytes |
| Polyglot file (valid JPEG *and* valid PHP) | magic bytes + optional image re-encode |
| Known malware | ClamAV signatures |
| Zip bomb, Zip Slip, nested archive abuse | archive inspection with hard limits |
| Image decompression bomb | pixel limit |
| SVG carrying script | separate SVG inspection |
| PDF with JavaScript, embedded files, launch actions | PDF capability reporting |
| Stored XSS in rich text you re-render | HTML sanitizer (a parser) |
| `javascript:` / `data:` URLs | URL scheme allowlist |
| Credential-phishing URLs, homograph domains | URL inspection |
| SSRF to internal or metadata addresses | opt-in SSRF mode (with caveats) |
| A dangerous file reaching normal storage | quarantine-first flow |
| No record of what happened | audit trail, events, structured logs |

## What it does not cover

**SQL injection.** Parameterised queries prevent SQL injection. The
suspicious-content scanner recognises payload shapes as an alerting signal. It
is not a control and must not be described as one.

**XSS in your own templates.** Contextual output escaping prevents XSS. The
sanitizer covers markup you deliberately accept and re-render, and nothing
else.

**Unknown malware.** The package orchestrates a signature engine. Signatures
catch known malware; a novel or targeted sample passes. There is no heuristic
here pretending otherwise.

**Encrypted or heavily obfuscated content.** An encrypted PDF or password-
protected archive cannot be inspected. It is reported as such, not waved
through.

**Compressed PDF object streams.** Markers hidden inside compressed object
streams are invisible to a non-rendering inspector. That is what the malware
engine is for.

**Authorization.** Who may upload, who may download, who may open the console
— all yours.

**Execution.** If your web server executes files out of an upload directory,
nothing in PHP can save you.

**Everything else in the list at the top of the README.**

## Design commitments

Each of these has a test. A reproducible breach of any is a vulnerability —
see [SECURITY.md](../SECURITY.md).

1. **Fail closed.** A scanner that cannot answer never yields a clean verdict.
2. **Generated paths.** A physical storage path is never derived from an
   uploader-supplied filename.
3. **Parse, don't match.** HTML is sanitized by a parser, never by a regex.
4. **Allowlist.** Extensions are allowlisted, and `forbidden_extensions`
   cannot be widened from the console or the database.
5. **Deny by default.** The console denies until authorization is configured,
   and answers 404 rather than 403.
6. **Quiet errors.** End-user messages never name the signature or the check.
7. **No payload propagation.** Scanned text and file contents never reach
   logs, mail, events or metadata.
8. **Audited release.** Releasing a quarantined file needs a fresh clean scan,
   or an explicitly requested and audited override.
9. **Bounded work.** Malformed input produces a failed check, never a crashed
   worker, an exhausted heap or a filled disk.

## Protecting the scanner itself

Limits exist because the scanner is also an attack surface:

- per-policy maximum size, checked first
- archive depth, file count, uncompressed size and compression ratio
- a bounded copy for nested archives
- a byte budget for PDF marker scanning
- a pixel ceiling for images
- a URL count ceiling in text scanning
- socket timeouts and job timeouts
- every check wrapped so a throw becomes a failed result

Run scanning on its own queue and its own workers. Malformed input is the
normal case here.

## Reporting

See [SECURITY.md](../SECURITY.md). Do not open a public issue.
