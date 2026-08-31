<?php

declare(strict_types=1);

use LaravelPlus\ContentSecurity\Contracts\UrlInspector;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

function inspectUrl(string $url): Findings
{
    return app(UrlInspector::class)->inspect($url);
}

it('accepts ordinary web addresses', function (string $url): void {
    expect(inspectUrl($url)->isEmpty())->toBeTrue();
})->with([
    'https://jobly.si',
    'https://jobly.si/oglasi/backend-developer?utm_source=x',
    'http://example.com:8080/path',
]);

it('rejects dangerous schemes', function (string $url): void {
    $findings = inspectUrl($url);

    expect($findings->hasAtLeast(ThreatLevel::High))->toBeTrue();
})->with([
    'javascript:alert(1)',
    'data:text/html;base64,PHNjcmlwdD4=',
    'file:///etc/passwd',
    'vbscript:msgbox(1)',
]);

it('flags credentials embedded in the URL', function (): void {
    // The phishing classic: everything before the @ is ignored by the browser.
    $findings = inspectUrl('https://trusted-bank.si@evil.example/login');

    expect($findings->hasAtLeast(ThreatLevel::High))->toBeTrue();
});

it('flags punycode and mixed-script hosts', function (string $url): void {
    expect(inspectUrl($url)->isEmpty())->toBeFalse();
})->with([
    'https://xn--80ak6aa92e.com',
    'https://аpple.com',
]);

it('ignores private addresses unless SSRF protection is on', function (): void {
    expect(inspectUrl('http://169.254.169.254/latest/meta-data/')->isEmpty())->toBeTrue();
});

it('blocks internal destinations in SSRF mode', function (string $url): void {
    config()->set('content-security.urls.ssrf_protection', true);
    app()->forgetInstance(UrlInspector::class);

    expect(inspectUrl($url)->hasAtLeast(ThreatLevel::High))->toBeTrue();
})->with([
    'http://127.0.0.1/admin',
    'http://localhost:9200/_cluster/health',
    'http://10.0.0.5/internal',
    'http://192.168.1.1/',
    'http://172.16.4.4/',
    // The cloud metadata endpoint — the single most exploited SSRF target.
    'http://169.254.169.254/latest/meta-data/',
    'http://[::1]:8080/',
]);

it('rejects malformed input', function (string $url): void {
    expect(inspectUrl($url)->isEmpty())->toBeFalse();
})->with([
    'not a url at all',
    "https://exa\nmple.com",
    '',
]);
