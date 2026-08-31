# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅        |

## Reporting a vulnerability

**Do not open a public issue.**

Email **nejc.cotic@gmail.com** with `[content-security]` in the subject, or
use GitHub's [private vulnerability reporting](https://github.com/LaravelPlus/content-security/security/advisories/new).

Please include:

- the version and PHP/Laravel versions
- what an attacker gains
- the smallest reproduction you can manage
- any relevant configuration (policy, driver, disk)

If a proof of concept involves a malicious file, describe it — do not attach
it.

You can expect an acknowledgement within 72 hours and an assessment within
seven days. Fixes ship as a patch release with an advisory crediting you,
unless you would rather not be named.

## What counts as a vulnerability here

In scope:

- a bypass that gets a file past a policy that should have rejected it
- HTML that survives the sanitizer and executes in a browser
- a URL the SSRF checks pass that reaches internal infrastructure
- reading or releasing a quarantined file without authorization
- a runtime policy override that widens a control it is documented not to
- the console leaking data to a user the auth callback rejects
- a malformed input that crashes a queue worker or exhausts memory or disk

Out of scope, because the package does not claim them:

- **SQL injection that the text scanner did not catch.** It is a heuristic
  signal, not a control. Parameterised queries prevent SQL injection.
- **XSS in your own templates.** Contextual output escaping prevents XSS.
  The sanitizer only covers markup you deliberately re-render.
- **Malware the engine did not recognise.** The package orchestrates ClamAV;
  it does not write signatures. Missed detections belong upstream.
- **Anything with `fail_closed` turned off**, or with the `null` malware
  driver in production.
- Findings that require an attacker to already hold admin credentials for the
  console, unless they escalate beyond what an admin may legitimately do.

## Design commitments

These are properties the package intends to hold. A reproducible breach of
any of them is a vulnerability, and each has a test:

1. A scanner that cannot answer never produces a clean verdict.
2. A physical storage path is never derived from an uploader-supplied
   filename.
3. HTML is sanitized by a parser. Never by a regex.
4. Extensions are allowlisted, and `forbidden_extensions` cannot be widened
   from the console or the database.
5. The admin console denies by default.
6. End-user validation messages never name the signature or the check.
7. Scanned text and file contents never reach logs, mail, or metadata.
8. Releasing a quarantined file requires a fresh clean scan, or an explicitly
   requested and audited override.
