# Admin console

Mounted at `/admin/content-security`.

```dotenv
CONTENT_SECURITY_ADMIN_PREFIX=admin/security
CONTENT_SECURITY_ADMIN_ENABLED=true
```

## Publishing

```bash
php artisan content-security:publish-pages
npm run build
```

The Vue pages land in `resources/js/pages/admin/content-security` — where your
Vite build already looks for Inertia pages. Once published they are yours;
edit them freely.

If your app maps page names to persistent layouts, exclude the console. It
ships its own full-page shell, and without this you get a shell inside a
shell:

```ts
case name.startsWith('admin/content-security/'):
    return undefined;
```

## Authorization

The package has no opinion about your authorization model and will not guess
one. **It denies everyone until you tell it otherwise.**

```php
ContentSecurity::auth(fn (?User $user): bool => $user?->isAdmin() ?? false);
```

Or a Gate ability:

```php
'admin' => ['gate' => 'viewSecurityConsole'],
```

Plus the usual middleware:

```php
'middleware' => ['web', 'auth', 'verified', 'role:admin'],
```

Unauthorised visitors get **404, not 403**. Confirming that a security console
exists at this URL is itself information they should not have.

## Pages

**Overview** — security posture, counters over a chosen window, scan volume,
scanner health, recent scans and latest findings. The headline treats scan
*failures* as seriously as detections: a fail-closed app with a dead engine is
rejecting every upload, and "no threats detected" would describe that
reassuringly and wrongly.

**Scans** — searchable and filterable by status, type, scanner, MIME, threat
level and date. Search covers filename, scan id and SHA-256.

**Scan detail** — the file's identity, the per-check breakdown with timings,
every finding, and a timeline.

**Threats** — aggregated by signature. Forty occurrences of one finding is one
thing to look at, not forty.

**Quarantine** — rescan, release, delete. Destructive actions confirm; delete
requires typing `DELETE`; an override requires a written reason.

**Policies** — config baseline and runtime overrides, each labelled by source.

**Scanner health** — engine state, version, signature age, ping, the active
pipeline, and the PHP extensions it depends on. The **Test scanner** button
sends the EICAR string.

## Paths

Filesystem paths are hidden by default:

```php
'admin' => ['expose_paths' => false],
```

Quarantine paths are generated ULIDs and reveal nothing about the uploader,
but they are operational detail and the default is to withhold them.

## JSON

Every console page answers JSON when asked, which is how you check a number
without reading a rendered page:

```bash
curl -H "Accept: application/json" https://example.com/admin/content-security
```

## Design

Dark mode, responsive, no emoji as icons (inline SVG on a 24px grid, no icon
dependency imposed on your app). Status is never conveyed by colour alone —
each carries its own icon and its own word, so the tables read correctly in
greyscale.
