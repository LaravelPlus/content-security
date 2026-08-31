@php
    /** @var \LaravelPlus\ContentSecurity\Reports\SecurityReport $report */
    $counts = $report->counts;
    $accent = $report->isHealthy() && ! $report->hasOfflineScanner() ? '#047857' : '#b91c1c';
@endphp
<x-mail::message>
# {{ __('content-security::report.greeting') }}

**{{ $report->from->toDayDateTimeString() }} — {{ $report->to->toDayDateTimeString() }}**

@if ($report->isQuiet())
{{ __('content-security::report.no_activity') }}
@else

<table width="100%" cellpadding="8" cellspacing="0" style="border-collapse:collapse;margin:16px 0;">
    <tr>
        <td style="border:1px solid #e5e7eb;"><strong>{{ __('content-security::report.scans') }}</strong></td>
        <td style="border:1px solid #e5e7eb;text-align:right;">{{ number_format($counts['total']) }}</td>
    </tr>
    <tr>
        <td style="border:1px solid #e5e7eb;">{{ __('content-security::report.clean') }}</td>
        <td style="border:1px solid #e5e7eb;text-align:right;">{{ number_format($counts['clean']) }}</td>
    </tr>
    <tr>
        <td style="border:1px solid #e5e7eb;">{{ __('content-security::report.suspicious') }}</td>
        <td style="border:1px solid #e5e7eb;text-align:right;">{{ number_format($counts['suspicious']) }}</td>
    </tr>
    <tr>
        <td style="border:1px solid #e5e7eb;color:{{ $counts['infected'] > 0 ? '#b91c1c' : 'inherit' }};">
            <strong>{{ __('content-security::report.infected') }}</strong>
        </td>
        <td style="border:1px solid #e5e7eb;text-align:right;color:{{ $counts['infected'] > 0 ? '#b91c1c' : 'inherit' }};">
            <strong>{{ number_format($counts['infected']) }}</strong>
        </td>
    </tr>
    <tr>
        <td style="border:1px solid #e5e7eb;">{{ __('content-security::report.quarantined') }}</td>
        <td style="border:1px solid #e5e7eb;text-align:right;">{{ number_format($counts['quarantined']) }}</td>
    </tr>
    <tr>
        <td style="border:1px solid #e5e7eb;">{{ __('content-security::report.failed') }}</td>
        <td style="border:1px solid #e5e7eb;text-align:right;">{{ number_format($counts['failed']) }}</td>
    </tr>
    <tr>
        <td style="border:1px solid #e5e7eb;">{{ __('content-security::report.avg_duration') }}</td>
        <td style="border:1px solid #e5e7eb;text-align:right;">{{ number_format($report->averageDurationMs, 1) }} ms</td>
    </tr>
</table>

@if ($report->hasFailures())
> **{{ __('content-security::report.failures_warning') }}**
@endif

@if ($report->isHealthy())
{{ __('content-security::report.healthy') }}
@endif

@if (count($report->topThreats) > 0)
## {{ __('content-security::report.top_threats') }}

<table width="100%" cellpadding="8" cellspacing="0" style="border-collapse:collapse;">
@foreach ($report->topThreats as $threat)
    <tr>
        <td style="border:1px solid #e5e7eb;">{{ $threat['name'] }}</td>
        <td style="border:1px solid #e5e7eb;">{{ ucfirst($threat['level']) }}</td>
        <td style="border:1px solid #e5e7eb;text-align:right;">{{ number_format($threat['occurrences']) }}</td>
    </tr>
@endforeach
</table>
@endif
@endif

@if (count($report->scanners) > 0)
## {{ __('content-security::report.scanner_health') }}

<table width="100%" cellpadding="8" cellspacing="0" style="border-collapse:collapse;">
@foreach ($report->scanners as $scanner)
    <tr>
        <td style="border:1px solid #e5e7eb;">{{ $scanner->scanner }}</td>
        <td style="border:1px solid #e5e7eb;text-transform:uppercase;">{{ $scanner->status() }}</td>
        <td style="border:1px solid #e5e7eb;">{{ $scanner->version ?? '—' }}</td>
    </tr>
@endforeach
</table>
@endif

@if ($consoleUrl !== null)
<x-mail::button :url="$consoleUrl" color="{{ $report->isHealthy() ? 'success' : 'error' }}">
{{ __('content-security::report.view_console') }}
</x-mail::button>
@endif
</x-mail::message>
