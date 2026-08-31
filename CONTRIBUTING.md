# Contributing

Thanks for helping. This is a security package, so a few things matter more
here than they might elsewhere.

## Getting set up

```bash
git clone git@github.com:LaravelPlus/content-security.git
cd content-security
composer install

composer test      # Pest
composer analyse   # PHPStan level 8
composer lint      # Pint
```

The suite must pass without ClamAV installed. Use `FakeMalwareScanner`; tests
that need a real daemon belong in the `Integration` suite.

## Standards

- `declare(strict_types=1);` in every PHP file.
- Full parameter and return types. Avoid `mixed` unless genuinely unavoidable.
- Classes are `final` unless designed for extension (the `Abstract*` checks).
- Depend on the contracts in `src/Contracts`, not on concrete classes.
- Value objects over associative arrays for anything crossing a boundary.
- No static global state, no service locator inside domain services, no
  `app()` in a class that could take a constructor argument.
- PHPStan level 8 with no new suppressions. If you need one, explain why in
  the pull request rather than in a `@phpstan-ignore` comment.

## Comments

Comment the *why*, not the *what*. The valuable comment in this codebase is
the one that explains a security decision or a non-obvious constraint —
why the malware check runs last, why a breach is reported once rather than
per entry, why the console answers 404 instead of 403. Skip the ones that
restate the code.

## Security-relevant changes

If your change touches any of these, say so explicitly in the pull request
and add a test that fails without your change:

- the check pipeline or its order
- policy resolution or the override screening
- quarantine paths, release, or deletion
- the HTML sanitizer configuration
- validation-rule messages
- console authorization

Some specific rules:

- **Never** loosen `forbidden_extensions` screening.
- **Never** make a failed scan read as clean.
- **Never** put file contents, scanned text, or a matched payload into a log
  line, an event, an email or a metadata field.
- **Never** derive a storage path from an uploader-supplied filename.
- **Never** replace the HTML sanitizer with pattern matching.

## Adding a check

Extend `AbstractFileCheck` or `AbstractTextCheck`. Report findings; do not
score them — severity is the base class's job so every check answers "how bad
is this?" the same way.

```php
final class MyCheck extends AbstractFileCheck
{
    public function key(): string { return 'my_check'; }

    public function label(): string { return 'My check'; }

    protected function inspect(FileReference $file, FilePolicy $policy, ScanContext $context): Findings
    {
        return Findings::none(['looked_at' => true]);
    }
}
```

Throwing is fine — the base class turns it into a failed check. Returning a
pass when you could not actually check is not.

## Pull requests

One concern per pull request. Include tests. Update the README when you change
behaviour a user can see. If you found a bug, add the failing test first so
the fix is demonstrably a fix.

## Reporting a vulnerability

Do not open an issue — see [SECURITY.md](SECURITY.md).
