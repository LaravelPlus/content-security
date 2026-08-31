# Installation

## Requirements

| | |
| --- | --- |
| PHP | 8.5+ |
| Laravel | 13 |
| `ext-fileinfo` | required — server-side type detection |
| `ext-zip` | archives (without it, archive checks report unavailable) |
| `ext-gd` | image decoding and re-encoding |
| ClamAV | optional, strongly recommended |
| `inertiajs/inertia-laravel` | the admin console |

## Install

```bash
composer require laravelplus/content-security
php artisan content-security:install
php artisan migrate
```

`content-security:install` publishes the config and migrations. Add `--pages`
to publish the Vue console at the same time. It never runs migrations or edits
`.env` for you.

## Configure

```dotenv
CONTENT_SECURITY_ENABLED=true
CONTENT_SECURITY_FAIL_CLOSED=true
CONTENT_SECURITY_MALWARE_DRIVER=clamav

CONTENT_SECURITY_CLAMAV_CONNECTION=unix
CONTENT_SECURITY_CLAMAV_SOCKET=/var/run/clamav/clamd.ctl

CONTENT_SECURITY_QUARANTINE_DISK=local
CONTENT_SECURITY_ADMIN_PREFIX=admin/content-security
CONTENT_SECURITY_REPORT_TO=security@example.com
```

Use the `null` driver in local and CI. It reports every file as *skipped*,
never as clean — a machine without an engine must not be able to tell itself
its uploads were scanned.

## Verify

```bash
php artisan content-security:status
```

It prints the configuration, engine state, the active pipeline and recent
activity — and warns about the things that quietly defeat the package:
scanning disabled, `fail_closed` off, the null driver in production, or a
quarantine disk that looks web-served.

```bash
php artisan content-security:health   # exit non-zero if an enabled engine is down
```

## ClamAV

### Debian / Ubuntu

```bash
sudo apt install clamav clamav-daemon
sudo systemctl enable --now clamav-freshclam
sudo systemctl enable --now clamav-daemon
```

The daemon must be able to read the socket as your PHP user:

```bash
sudo usermod -aG clamav www-data
```

### Docker

```yaml
services:
  clamav:
    image: clamav/clamav:stable
    ports: ['3310:3310']
    # clamd holds the whole signature database in memory.
    deploy:
      resources:
        limits:
          memory: 2G
```

```dotenv
CONTENT_SECURITY_CLAMAV_CONNECTION=tcp
CONTENT_SECURITY_CLAMAV_HOST=clamav
CONTENT_SECURITY_CLAMAV_PORT=3310
```

### Why the daemon, not the binary

`clamscan` reloads the entire signature database on every invocation —
roughly a second of CPU and several hundred MB of RAM per file. On an upload
endpoint that is a fork bomb with a large working set. The CLI fallback exists
(`cli_fallback`) and is off by default; leave it off in production.

### Large files

`clamd` refuses INSTREAM payloads above its own `StreamMaxLength`. Keep the
package's `max_stream_size` at or below it, and raise both together if you
accept large uploads:

```
# /etc/clamav/clamd.conf
StreamMaxLength 200M
MaxFileSize 200M
MaxScanSize 400M
```

## Testing the engine

From the console: **Scanner health → Test scanner**. It sends the EICAR test
string — 68 printable ASCII characters that every engine is required to flag
and which do nothing if executed. It proves the engine is reachable *and*
actually matching, which a ping does not.
