@php
    /** @var \LaravelPlus\ContentSecurity\Reports\SecurityReport $report */
    $counts = $report->counts;
    $offline = collect($report->scanners)->filter(fn ($s) => $s->enabled && ! $s->online)->pluck('scanner')->implode(', ');
@endphp
<x-mail::message>
@if ($report->isQuiet() && $offline === '')
{{ __('content-security::report.no_activity') }}
@elseif ($report->incidents === [] && $offline === '')
{{ __('content-security::report.healthy', ['total' => number_format($counts['total'])]) }}
@else
@if ($offline !== '')
**{{ __('content-security::report.offline_warning', ['names' => $offline]) }}**

@endif
@if ($report->hasFailures())
**{{ __('content-security::report.failures_warning') }}**

@endif
@foreach ($report->incidents as $i)
- **{{ __('content-security::report.'.$i['status']) }}** · {{ $i['at']->format('j. n. H:i') }} · {{ $i['subject'] }}@if ($i['policy']) ({{ $i['policy'] }})@endif @if ($i['user']) · {{ __('content-security::report.user', ['id' => $i['user']]) }}@endif @if ($i['threats'] !== []) — {{ implode(', ', $i['threats']) }}@endif @if ($i['error']) — {{ $i['error'] }}@endif

@endforeach
@if ($report->incidentsTotal > count($report->incidents))
{{ __('content-security::report.more', ['n' => $report->incidentsTotal - count($report->incidents)]) }}
@endif
@if ($consoleUrl !== null)

<x-mail::button :url="$consoleUrl" color="error">
{{ __('content-security::report.view_console') }}
</x-mail::button>
@endif
@endif
</x-mail::message>
