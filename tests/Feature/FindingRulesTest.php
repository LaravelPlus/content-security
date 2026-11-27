<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Notification;
use LaravelPlus\ContentSecurity\Contracts\MalwareScanner;
use LaravelPlus\ContentSecurity\Domain\Policy\FindingRules;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Exceptions\InvalidFindingRuleException;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Notifications\FindingAlert;
use LaravelPlus\ContentSecurity\Reports\SecurityReport;
use LaravelPlus\ContentSecurity\Tests\Support\FakeMalwareScanner;

beforeEach(function (): void {
    ContentSecurity::extend('clamav', fn (): MalwareScanner => FakeMalwareScanner::clean());
    config()->set('content-security.malware.default', 'clamav');
    config()->set('content-security.malware.drivers.clamav', ['driver' => 'clamav']);
});

function ruledScan(string $name, string $contents = 'perfectly ordinary', ?string $policy = null): ScanResult
{
    $directory = sys_get_temp_dir().'/cs-rules-'.bin2hex(random_bytes(6));
    mkdir($directory);
    file_put_contents($directory.'/'.$name, $contents);

    return ContentSecurity::scanFile($directory.'/'.$name, $policy);
}

/** @return list<string> */
function ruledThreatNames(ScanResult $result): array
{
    return array_map(fn ($threat) => $threat->name, $result->threats());
}

it('keeps the severity default when no rule is configured', function (): void {
    $result = ruledScan('invoice.pdf.txt');

    expect($result->isClean())->toBeFalse()
        ->and(ruledThreatNames($result))->toContain('file.multiple_extensions');
});

it('lets an allow rule record a finding without blocking', function (): void {
    config()->set('content-security.findings', ['file.multiple_extensions' => ['action' => 'allow']]);

    $result = ruledScan('invoice.pdf.txt');

    expect($result->isClean())->toBeTrue()
        ->and(ruledThreatNames($result))->toContain('file.multiple_extensions')
        ->and($result->threats()[0]->metadata)->toMatchArray(['action' => 'allow', 'notify' => 'digest']);
});

it('lets a policy rule win over the global one for the same code', function (): void {
    config()->set('content-security.findings', ['file.multiple_extensions' => ['action' => 'reject']]);
    config()->set('content-security.files.policies.default.findings', ['file.multiple_extensions' => ['action' => 'allow']]);

    expect(ruledScan('invoice.pdf.txt')->isClean())->toBeTrue()
        ->and(ruledScan('invoice.pdf.txt', policy: 'documents')->isClean())->toBeFalse();
});

it('routes a finding to reject or quarantine regardless of on_threat', function (): void {
    // default policy quarantines; a reject rule discards instead.
    config()->set('content-security.findings', ['file.multiple_extensions' => ['action' => 'reject']]);
    expect(ruledScan('invoice.pdf.txt')->status())->toBe(ScanStatus::Suspicious);

    // documents policy is switched to reject; a quarantine rule keeps the file.
    config()->set('content-security.files.policies.documents.on_threat', 'reject');
    config()->set('content-security.findings', ['file.multiple_extensions' => ['action' => 'quarantine']]);
    expect(ruledScan('invoice.pdf.txt', policy: 'documents')->status())->toBe(ScanStatus::Quarantined);
});

it('resolves several findings to the strongest action', function (): void {
    // A reject rule on one finding must not discard evidence that an
    // unruled finding (policy on_threat = quarantine) asks to keep.
    config()->set('content-security.findings', ['file.multiple_extensions' => ['action' => 'reject']]);

    $result = ruledScan('invoice.pdf.txt', '<?php system($_GET["c"]);');

    expect(ruledThreatNames($result))->toContain('file.multiple_extensions')
        ->and(count($result->threats()))->toBeGreaterThan(1)
        ->and($result->status())->toBe(ScanStatus::Quarantined);
});

it('refuses to downgrade a hard safety control to allow', function (): void {
    FindingRules::fromConfig(['file.executable_extension' => ['action' => 'allow']]);
})->throws(InvalidFindingRuleException::class, 'hard safety control');

it('still lets a hard safety control be notified immediately', function (): void {
    expect(FindingRules::fromConfig(['file.executable_extension' => ['action' => 'quarantine', 'notify' => 'immediate']]))
        ->toBeInstanceOf(FindingRules::class);
});

it('rejects unknown codes, actions, modes and keys', function (array $rules, string $message): void {
    expect(fn () => FindingRules::fromConfig($rules))->toThrow(InvalidFindingRuleException::class, $message);
})->with([
    'code' => [['file.made_up' => ['action' => 'allow']], 'Unknown finding code'],
    'action' => [['file.multiple_extensions' => ['action' => 'ignore']], 'unknown action'],
    'notify' => [['file.multiple_extensions' => ['notify' => 'sms']], 'unknown notify mode'],
    'key' => [['file.multiple_extensions' => ['actoin' => 'allow']], 'unknown keys'],
    'shape' => [['file.multiple_extensions' => 'allow'], 'must be an array'],
]);

it('mails immediate findings once per scan', function (): void {
    Notification::fake();
    config()->set('content-security.reports.recipients', 'ops@example.test');
    config()->set('content-security.findings', ['file.multiple_extensions' => ['notify' => 'immediate']]);

    ruledScan('invoice.pdf.txt');

    Notification::assertSentOnDemandTimes(FindingAlert::class, 1);
});

it('sends no immediate mail for digest findings or without recipients', function (): void {
    Notification::fake();
    config()->set('content-security.findings', ['file.multiple_extensions' => ['notify' => 'immediate']]);
    ruledScan('invoice.pdf.txt');

    config()->set('content-security.reports.recipients', 'ops@example.test');
    config()->set('content-security.findings', []);
    ruledScan('invoice.pdf.txt');

    Notification::assertNothingSent();
});

it('leaves notify none findings out of the digest', function (): void {
    config()->set('content-security.findings', ['file.multiple_extensions' => ['action' => 'reject', 'notify' => 'none']]);
    ruledScan('invoice.pdf.txt');

    config()->set('content-security.findings', []);
    ruledScan('report.pdf.txt');

    $report = SecurityReport::build('weekly', now()->subDay()->toImmutable(), now()->addMinute()->toImmutable());

    expect($report->incidents)->toHaveCount(1)
        ->and($report->incidents[0]['subject'])->toBe('report.pdf.txt')
        ->and($report->topThreats[0]['occurrences'])->toBe(1);
});
