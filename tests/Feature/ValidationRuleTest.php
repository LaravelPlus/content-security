<?php

declare(strict_types=1);

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Validator;
use LaravelPlus\ContentSecurity\Rules\SafeFile;
use LaravelPlus\ContentSecurity\Rules\SafeHtml;
use LaravelPlus\ContentSecurity\Rules\SafeText;
use LaravelPlus\ContentSecurity\Rules\SafeUrl;

function validate(array $data, array $rules): Illuminate\Validation\Validator
{
    return Validator::make($data, $rules);
}

it('passes a clean upload', function (): void {
    $file = UploadedFile::fake()->createWithContent('notes.txt', 'ordinary content');

    expect(validate(['f' => $file], ['f' => [new SafeFile]])->passes())->toBeTrue();
});

it('rejects a dangerous upload', function (): void {
    $file = UploadedFile::fake()->createWithContent('shell.php', '<?php system($_GET["c"]);');

    expect(validate(['f' => $file], ['f' => [new SafeFile]])->passes())->toBeFalse();
});

it('never leaks the signature or check name to the end user', function (): void {
    $file = UploadedFile::fake()->createWithContent('shell.php', '<?php system($_GET["c"]);');

    $validator = validate(['f' => $file], ['f' => [new SafeFile]]);
    $message = $validator->errors()->first('f');

    // An error that named the rule would turn the endpoint into a probe
    // that tells an attacker which attempt got closest.
    expect($message)->not->toContain('executable_extension')
        ->and($message)->not->toContain('php')
        ->and($message)->not->toContain('ClamAV')
        ->and($message)->toContain('security check');
});

it('exposes the full result to the developer', function (): void {
    $rule = new SafeFile;
    validate(['f' => UploadedFile::fake()->createWithContent('shell.php', 'x')], ['f' => [$rule]])->passes();

    expect($rule->result())->not->toBeNull()
        ->and($rule->result()->isClean())->toBeFalse()
        ->and($rule->result()->threats())->not->toBeEmpty();
});

it('honours a named policy', function (): void {
    // A minimal but *complete* PDF: without the %%EOF marker the PDF check
    // correctly flags it as truncated, which is not what this test is about.
    $file = UploadedFile::fake()->createWithContent(
        'report.pdf',
        "%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF",
    );

    // Allowed by the default policy, not by the images one.
    expect(validate(['f' => $file], ['f' => [new SafeFile]])->passes())->toBeTrue()
        ->and(validate(['f' => $file], ['f' => [new SafeFile('images')]])->passes())->toBeFalse();
});

it('validates text', function (): void {
    expect(validate(['t' => 'An ordinary sentence.'], ['t' => [new SafeText]])->passes())->toBeTrue()
        ->and(validate(['t' => '<script>alert(1)</script>'], ['t' => [new SafeText]])->passes())->toBeFalse();
});

it('validates html and exposes the sanitized version', function (): void {
    $rule = new SafeHtml;

    expect(validate(['h' => '<p>Fine</p>'], ['h' => [new SafeHtml]])->passes())->toBeTrue();

    validate(['h' => '<p>Hi</p><script>alert(1)</script>'], ['h' => [$rule]])->passes();

    expect($rule->sanitized())->not->toBeNull()
        ->and($rule->sanitized())->not->toContain('<script');
});

it('validates urls', function (): void {
    $safe = app(SafeUrl::class);

    expect(validate(['u' => 'https://jobly.si'], ['u' => [$safe]])->passes())->toBeTrue()
        ->and(validate(['u' => 'javascript:alert(1)'], ['u' => [app(SafeUrl::class)]])->passes())->toBeFalse();
});

it('gives a URL a specific, useful message', function (): void {
    $validator = validate(['u' => 'javascript:alert(1)'], ['u' => [app(SafeUrl::class)]]);
    $validator->passes();

    // URLs are the one case where naming the problem is safe: the user
    // typed it and can see it.
    expect($validator->errors()->first('u'))->toContain('http');
});

it('passes everything through when scanning is disabled', function (): void {
    config()->set('content-security.enabled', false);

    $file = UploadedFile::fake()->createWithContent('shell.php', '<?php echo 1;');

    expect(validate(['f' => $file], ['f' => [new SafeFile]])->passes())->toBeTrue();
});

it('ignores non-file and non-string values', function (): void {
    expect(validate(['f' => null], ['f' => ['nullable', new SafeFile]])->passes())->toBeTrue()
        ->and(validate(['t' => null], ['t' => ['nullable', new SafeText]])->passes())->toBeTrue();
});
