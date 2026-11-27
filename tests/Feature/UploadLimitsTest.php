<?php

declare(strict_types=1);

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Validator;
use LaravelPlus\ContentSecurity\Contracts\MalwareScanner;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Repositories\DatabasePolicyRepository;
use LaravelPlus\ContentSecurity\Rules\SafeFile;
use LaravelPlus\ContentSecurity\Support\Bytes;
use LaravelPlus\ContentSecurity\Tests\Support\FakeMalwareScanner;

beforeEach(function (): void {
    ContentSecurity::extend('clamav', fn (): MalwareScanner => FakeMalwareScanner::clean());
    config()->set('content-security.malware.default', 'clamav');
    config()->set('content-security.malware.drivers.clamav', ['driver' => 'clamav']);

    config()->set('content-security.files.policies.support', [
        'max_size' => '1 KB',
        'max_files' => 3,
        'max_total_size' => '2 KB',
        'extensions' => ['txt'],
    ]);
});

/** A text upload of the given size in bytes. */
function upload(int $bytes, string $name = 'notes.txt'): UploadedFile
{
    return UploadedFile::fake()->createWithContent($name, str_repeat('a', $bytes));
}

function check(mixed $value, SafeFile $rule): Illuminate\Validation\Validator
{
    return Validator::make(['f' => $value], ['f' => [$rule]]);
}

it('parses human sizes with binary units', function (mixed $input, int $bytes): void {
    expect(Bytes::parse($input))->toBe($bytes);
})->with([
    [1024, 1024],
    ['2048', 2048],
    ['500 KB', 500 * 1024],
    ['10 MB', 10 * 1024 * 1024],
    ['10MiB', 10 * 1024 * 1024],
    ['2 gb', 2 * 1024 ** 3],
    ['1.5 MB', 1_572_864],
]);

it('rejects invalid sizes', function (mixed $input): void {
    expect(fn () => Bytes::parse($input))->toThrow(InvalidArgumentException::class);
})->with(['', 'ten MB', '10 XB', '-1', 0, '0 KB', null, 1.5]);

it('reads human sizes and batch limits from policy config', function (): void {
    $policy = FilePolicy::named('support');

    expect($policy->maxSize)->toBe(1024)
        ->and($policy->maxFiles)->toBe(3)
        ->and($policy->maxTotalSize)->toBe(2048)
        ->and(FilePolicy::named('default')->maxFiles)->toBeNull()
        ->and(FilePolicy::named('default')->maxTotalSize)->toBeNull();
});

it('fails loudly on an invalid size in policy config', function (): void {
    config()->set('content-security.files.policies.support.max_size', 'lots');

    FilePolicy::named('support');
})->throws(InvalidArgumentException::class);

it('applies the policy size limit per file', function (): void {
    expect(check(upload(1000), new SafeFile('support'))->passes())->toBeTrue()
        ->and(check(upload(1100), new SafeFile('support'))->passes())->toBeFalse();
});

it('accepts a batch within the policy count and total', function (): void {
    expect(check([upload(600), upload(600), upload(600)], new SafeFile('support'))->passes())->toBeTrue();
});

it('rejects a batch with too many files', function (): void {
    $validator = check([upload(10), upload(10), upload(10), upload(10)], new SafeFile('support'));

    expect($validator->passes())->toBeFalse()
        ->and($validator->errors()->first('f'))->toContain('Too many files');
});

it('rejects a batch over the total size even when each file fits', function (): void {
    $validator = check([upload(900), upload(900), upload(900)], new SafeFile('support'));

    expect($validator->passes())->toBeFalse()
        ->and($validator->errors()->first('f'))->toContain('2.0 KB');
});

it('scans every file in a batch', function (): void {
    $rule = new SafeFile('support');

    expect(check([upload(10), upload(10, 'shell.php')], $rule)->passes())->toBeFalse()
        ->and($rule->result()?->isClean())->toBeFalse();
});

it('lets a field tighten the policy but never widen it', function (): void {
    // Tighter: the field limit wins.
    expect(check(upload(600), (new SafeFile('support'))->maxSize('512 B'))->passes())->toBeFalse()
        ->and(check([upload(10), upload(10)], (new SafeFile('support'))->maxFiles(1))->passes())->toBeFalse()
        ->and(check([upload(600), upload(600)], (new SafeFile('support'))->maxTotalSize('1 KB'))->passes())->toBeFalse();

    // Wider: the policy still applies.
    expect(check(upload(1100), (new SafeFile('support'))->maxSize('10 MB'))->passes())->toBeFalse()
        ->and(check([upload(10), upload(10), upload(10), upload(10)], (new SafeFile('support'))->maxFiles(10))->passes())->toBeFalse()
        ->and(check([upload(900), upload(900), upload(900)], (new SafeFile('support'))->maxTotalSize('1 GB'))->passes())->toBeFalse();
});

it('uses different policies for different fields of one form', function (): void {
    $validator = Validator::make(
        ['avatar' => upload(1100, 'me.txt'), 'attachments' => [upload(1100)]],
        [
            'avatar' => [new SafeFile('default')],
            'attachments' => [new SafeFile('support')],
        ],
    );

    expect($validator->passes())->toBeFalse()
        ->and($validator->errors()->has('avatar'))->toBeFalse()
        ->and($validator->errors()->has('attachments'))->toBeTrue();
});

it('keeps forbidden extensions out whatever the field allows', function (): void {
    config()->set('content-security.files.policies.support.extensions', ['txt', 'php']);

    expect(check([upload(10, 'shell.php')], (new SafeFile('support'))->maxFiles(3))->passes())->toBeFalse();
});

it('keeps human sizes intact through a runtime policy override', function (): void {
    config()->set('content-security.files.max_size_ceiling', '1 MB');
    $repository = app(DatabasePolicyRepository::class);
    $repository->override('file', 'support', ['label' => 'Support uploads']);

    expect($repository->file('support')->maxSize)->toBe(1024);

    $repository->override('file', 'support', ['max_size' => 5 * 1024 * 1024]);

    expect($repository->file('support')->maxSize)->toBe(1024 * 1024);
});
