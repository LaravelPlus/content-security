# Policies

A policy is what one upload slot or text field will accept.

## Config is the baseline

```php
'files' => [
    'default_policy' => 'default',

    'policies' => [
        'default' => [
            'label' => 'Default Upload Policy',
            'max_size' => 25 * 1024 * 1024,
            'extensions' => ['pdf', 'docx', 'jpg', 'png', /* … */],
            'mime_types' => [],          // empty = derive from extensions
            'checks' => [
                'size' => true, 'extension' => true, 'mime' => true,
                'magic_bytes' => true, 'archive' => true, 'image' => true,
                'pdf' => true, 'malware' => true,
            ],
            'on_threat' => 'quarantine',
        ],
    ],

    'max_size_ceiling' => 512 * 1024 * 1024,

    'forbidden_extensions' => ['php', 'phar', 'exe', 'sh', /* … */],
],
```

Allowlist, not blocklist. An extension not named is refused, which is the only
way to stay ahead of formats nobody has thought of yet.

An unlisted check defaults to **on**, so a check added in a future release
ships enabled rather than silently absent.

## Using one

```php
ContentSecurity::scanFile($file, 'images');
new SafeFile('documents');

FilePolicy::default();
FilePolicy::images();
FilePolicy::documents();
FilePolicy::named('avatars');
FilePolicy::custom(['pdf'], maxSize: 2 * 1024 * 1024);
```

## Runtime overrides

With `admin.manage_policies` on (the default), the database holds *overrides*
on top of the config baseline, edited from the console.

That layering is the whole design:

- A policy nobody has touched has **no row at all** and reads straight from
  config. Your deployment defaults stay the reviewed, version-controlled thing
  they should be.
- A row records only the fields someone actually changed. That is what makes
  **Reset** meaningful, and what keeps a config change — tightening the
  default max size in a release, say — visible to every policy that has not
  deliberately overridden it.
- `checks` merges key by key, so a newly shipped check is not switched off by
  an override written before it existed.

The console labels every policy `config` or `overridden`.

```php
$policies = app(PolicyRepository::class);

$policies->file('default');
$policies->isOverridden('file', 'default');
$policies->override('file', 'default', ['max_size' => 5 * 1024 * 1024], actorId: auth()->id(), note: 'Tightened after review');
$policies->reset('file', 'default');
```

Every change dispatches `PolicyChanged` — carrying both sides, because "the
allowlist was widened" needs a before and an after to be worth anything — and
is logged at warning level regardless of config.

## What cannot be overridden

Enforced in the repository, not in the UI, so it holds however the change
arrives:

- **`forbidden_extensions`.** Screened out of any allowlist on every read. A
  console that could add `php` would *be* the vulnerability.
- **`max_size_ceiling`.** An override is clamped to it.

The API request layer rejects both with a validation error too, so someone
typing `php` into the console is told rather than silently ignored.

## Turning editing off

```dotenv
CONTENT_SECURITY_MANAGE_POLICIES=false
```

The container binds `ConfigPolicyRepository`, the console renders read-only,
and the policy is reviewable in a diff and nowhere else. A perfectly
reasonable choice.

## Text policies

```php
'text' => [
    'policies' => [
        'default' => ['max_length' => 200_000, 'checks' => ['suspicious' => true, 'html' => false, 'urls' => true]],
        'rich'    => ['max_length' => 500_000, 'checks' => ['suspicious' => true, 'html' => true,  'urls' => true]],
    ],
],
```
