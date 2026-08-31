# Validation rules

```php
use LaravelPlus\ContentSecurity\Rules\{SafeFile, MalwareFree, SafeText, SafeHtml, SafeUrl};

$request->validate([
    'attachment'  => ['nullable', 'file', 'max:10240', new SafeFile()],
    'avatar'      => ['nullable', 'image', new SafeFile('images')],
    'description' => ['required', new SafeHtml()],
    'bio'         => ['required', 'string', new SafeText()],
    'website'     => ['nullable', app(SafeUrl::class)],
]);
```

Keep Laravel's own `file`, `image`, `mimes` and `max` rules alongside these.
They are cheaper and produce better messages; these are the layer behind them.

`SafeUrl` and `MalwareFree` take constructor dependencies, so resolve them
from the container (`app(SafeUrl::class)`) rather than newing them up.

## In a FormRequest

```php
final class StoreApplicationRequest extends FormRequest
{
    private SafeFile $cv;

    public function rules(): array
    {
        $this->cv = new SafeFile('documents');

        return [
            'cv' => ['required', 'file', 'mimes:pdf,doc,docx', 'max:10240', $this->cv],
            'cover_letter' => ['nullable', 'string', 'max:5000', new SafeText()],
        ];
    }

    /** The scan id, so the controller can record it against the application. */
    public function scanId(): ?string
    {
        return $this->cv->result()?->scanId()?->__toString();
    }
}
```

## Messages

User-facing messages are deliberately non-specific:

> This file did not pass a security check.

Naming the signature or the check would tell an attacker which attempt got
closest and turn the endpoint into a free malware sandbox. Full detail goes to
the audit log and the console.

URLs are the exception — see [url-security.md](url-security.md).

Override the wording by publishing the translations:

```bash
php artisan vendor:publish --tag=content-security-lang
```

English and Slovenian ship with the package.

## Reading the result

Every rule exposes what it found:

```php
$rule = new SafeFile();
$validator = Validator::make($data, ['f' => ['required', 'file', $rule]]);

$validator->passes();

$rule->result();      // ScanResult|null
$rule->result()->scanId();
$rule->result()->threats();
```

`SafeHtml` additionally gives you the cleaned markup:

```php
$rule->sanitized();   // string|null
```

## Which rule

| Rule | Use for |
| --- | --- |
| `SafeFile` | Any upload. The full pipeline under a named policy. |
| `MalwareFree` | The engine only, when surrounding validation already constrains the file. Prefer `SafeFile`. |
| `SafeText` | Plain-text fields. A heuristic tripwire — read [text-and-html.md](text-and-html.md). |
| `SafeHtml` | Rich text you will re-render. Consider `sanitizeHtml()` instead. |
| `SafeUrl` | User-supplied web addresses. |

## When scanning is disabled

With `CONTENT_SECURITY_ENABLED=false` every rule passes everything through.
Useful for an emergency rollback; not a state to sit in.
