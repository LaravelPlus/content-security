<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Mail;
use LaravelPlus\ContentSecurity\Contracts\MalwareScanner;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanType;
use LaravelPlus\ContentSecurity\Facades\ContentSecurity;
use LaravelPlus\ContentSecurity\Tests\Support\FakeMalwareScanner;
use Symfony\Component\Mime\Email;

/** Smallest well-formed PDF: the PDF check rightly flags one without %%EOF. */
function pdf(): string
{
    return "%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n";
}

function mailScanner(MalwareScanner $scanner): void
{
    ContentSecurity::extend('clamav', fn (): MalwareScanner => $scanner);
    config()->set('content-security.malware.default', 'clamav');
    config()->set('content-security.malware.drivers.clamav', ['driver' => 'clamav']);
}

/** What Laravel's markdown mail actually produces: a head, a style block, inline styles everywhere. */
function styledMail(): Email
{
    return (new Email)
        ->subject('Your invoice')
        ->text('Your invoice is attached. View it at http://localhost/invoices/1')
        ->html('<!DOCTYPE html><html><head><style>.button{color:#fff}</style></head><body style="margin:0">'
            .'<table width="100%" style="background:#f4f4f7"><tr><td style="padding:32px">'
            .'<a href="http://localhost/invoices/1" class="button" style="background:#2d3748">View invoice</a>'
            .'</td></tr></table></body></html>')
        ->attach(pdf(), 'invoice.pdf', 'application/pdf');
}

function parts(ScanResult $result): array
{
    return array_combine(
        array_map(fn ($check) => $check->check, $result->checks()),
        array_map(fn ($check) => $check->status, $result->checks()),
    );
}

it('passes an ordinary styled mail with an attachment', function (): void {
    mailScanner(FakeMalwareScanner::clean());

    $result = ContentSecurity::scanEmail(styledMail());

    expect($result->isClean())->toBeTrue()
        ->and($result->type())->toBe(ScanType::Email)
        ->and(array_keys(parts($result)))->toBe(['subject', 'text', 'html', 'attachment:invoice.pdf']);
});

it('reports the infected attachment and marks the whole mail', function (): void {
    mailScanner(FakeMalwareScanner::infected('Win.Test.EICAR_HDB-1'));

    $result = ContentSecurity::scanEmail(styledMail());

    expect($result->isClean())->toBeFalse()
        ->and(parts($result)['subject'])->toBe(ScanStatus::Clean)
        ->and(parts($result)['attachment:invoice.pdf'])->not->toBe(ScanStatus::Clean);

    $names = array_map(fn ($threat) => $threat->name, $result->threats());
    expect($names)->toContain('Win.Test.EICAR_HDB-1');
});

it('fails closed when the engine cannot scan an attachment', function (): void {
    mailScanner(FakeMalwareScanner::unavailable());

    expect(ContentSecurity::scanEmail(styledMail())->isClean())->toBeFalse();
});

it('flags hostile markup in the html body', function (): void {
    $result = ContentSecurity::scanEmail(
        (new Email)->subject('Hi')->html('<p>Hello</p><img src=x onerror="fetch(\'//evil\')">'),
    );

    expect($result->isClean())->toBeFalse()
        ->and(parts($result)['html'])->not->toBe(ScanStatus::Clean);
});

it('cancels outbound mail that is not clean, and only when switched on', function (): void {
    config()->set('mail.default', 'array');
    mailScanner(FakeMalwareScanner::infected());

    $send = fn () => Mail::raw('See attached.', fn ($message) => $message
        ->to('client@example.com')
        ->subject('Invoice')
        ->attachData(pdf(), 'invoice.pdf', ['mime' => 'application/pdf']));

    expect($send())->not->toBeNull();

    config()->set('content-security.mail.scan_outbound', true);

    expect($send())->toBeNull();
});

it('sends clean outbound mail when switched on', function (): void {
    config()->set('mail.default', 'array');
    config()->set('content-security.mail.scan_outbound', true);
    mailScanner(FakeMalwareScanner::clean());

    expect(Mail::raw('Hello there.', fn ($message) => $message->to('client@example.com')->subject('Hello')))
        ->not->toBeNull();
});

it('does not read css or prose as urls, but still catches payload schemes', function (string $text, bool $clean): void {
    expect(ContentSecurity::scanText($text)->isClean())->toBe($clean);
})->with([
    'inline css' => ['<td style="color:#fff;padding:32px">Hi</td>', true],
    'prose' => ['Meeting at time:10am, ratio 16:9', true],
    'https link' => ['See https://example.com/docs', true],
    'javascript uri' => ['click javascript:alert(1)', false],
    'data uri' => ['open data:text/html;base64,PHNjcmlwdD4=', false],
    'ftp link' => ['grab ftp://example.com/file', false],
]);
