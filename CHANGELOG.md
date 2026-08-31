# Changelog

All notable changes to `laravelplus/content-security` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- File security pipeline: size, extension, MIME, magic bytes, archive, image,
  PDF and malware checks, each configurable per policy.
- ClamAV driver over `clamd` (Unix socket or TCP) with a streaming INSTREAM
  implementation and an optional `clamscan` fallback.
- Archive inspection: compression bombs, path traversal, entry counts,
  uncompressed size, recursion depth and executable entries — read from the
  table of contents, never extracted.
- Image validation with pixel-bomb and trailing-data detection, optional
  re-encoding, and separate SVG handling.
- PDF capability reporting: JavaScript, embedded files, launch actions,
  auto-execute, encryption and object counts.
- HTML sanitization over `symfony/html-sanitizer`.
- URL validation with an optional SSRF-aware mode.
- Suspicious-content heuristics for untrusted text.
- Quarantine with generated ULID paths, audited release and deletion.
- Queue-based scanning with a fixed scan id, retries and terminal failure
  handling.
- Validation rules: `SafeFile`, `MalwareFree`, `SafeText`, `SafeHtml`,
  `SafeUrl`.
- Persistence and audit trail with privacy-preserving defaults.
- Runtime policy overrides layered on the config baseline, editable from the
  console and screened against `forbidden_extensions` and a size ceiling.
- Vue 3 + Inertia security console at `/admin/content-security`.
- Daily and weekly mail digests.
- Artisan commands: `status`, `scan`, `health`, `report`,
  `cleanup-quarantine`, `install`, `publish-pages`.
