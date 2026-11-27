<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Domain\Policy;

use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use LaravelPlus\ContentSecurity\Exceptions\InvalidFindingRuleException;

/**
 * Per-code enforcement and notification for file findings, from
 * `content-security.findings` with a policy's own `findings` on top.
 *
 * A code with no rule keeps the severity default: High and above blocks,
 * Low and Medium are suspicious (also blocking), Info only records. The
 * scan verdict a check reports is not rewritten until a rule says so, and
 * then only for that check.
 */
final readonly class FindingRules
{
    /**
     * Every code a file scan can raise. Malware signature names are not
     * listed: they come from the engine and always block.
     */
    public const array CODES = [
        'archive.compression_bomb', 'archive.executable_entry', 'archive.inspector_unavailable',
        'archive.max_depth', 'archive.null_byte_entry', 'archive.path_traversal',
        'archive.too_many_files', 'archive.uncompressed_size', 'archive.unreadable',
        'file.declared_mime_mismatch', 'file.embedded_php', 'file.empty', 'file.executable_content',
        'file.executable_extension', 'file.extension_not_allowed', 'file.mime_extension_mismatch',
        'file.mime_not_allowed', 'file.multiple_extensions', 'file.no_extension', 'file.too_large',
        'image.pixel_bomb', 'image.svg_doctype', 'image.svg_entity', 'image.svg_event_handler',
        'image.svg_foreign_object', 'image.svg_javascript_uri', 'image.svg_script',
        'image.svg_too_large', 'image.trailing_data', 'image.undecodable',
        'pdf.auto_execute', 'pdf.embedded_file', 'pdf.encrypted', 'pdf.excessive_objects',
        'pdf.javascript', 'pdf.launch_action', 'pdf.malformed', 'pdf.no_eof_marker',
    ];

    /**
     * Hard safety controls: executable content, the size ceiling and the
     * resource bounds. These may be routed to reject or quarantine, never
     * downgraded to `allow`.
     */
    public const array MANDATORY = [
        'archive.compression_bomb', 'archive.executable_entry', 'archive.max_depth',
        'archive.null_byte_entry', 'archive.path_traversal', 'archive.too_many_files',
        'archive.uncompressed_size', 'file.embedded_php', 'file.executable_content',
        'file.executable_extension', 'file.too_large', 'image.pixel_bomb',
        'image.svg_event_handler', 'image.svg_javascript_uri', 'image.svg_script',
    ];

    /**
     * @param  array<string, array{action: ?FindingAction, notify: FindingNotify}>  $rules
     */
    public function __construct(private array $rules = []) {}

    /**
     * @param  array<array-key, mixed>  $global  content-security.findings
     * @param  array<array-key, mixed>  $policy  the policy's own `findings`, wins per code
     */
    public static function fromConfig(array $global, array $policy = []): self
    {
        $rules = [];

        foreach ([$global, $policy] as $layer) {
            foreach ($layer as $code => $rule) {
                $rules[(string) $code] = [...($rules[(string) $code] ?? []), ...self::parse((string) $code, $rule)];
            }
        }

        return new self(array_map(static fn (array $rule): array => [
            'action' => $rule['action'] ?? null,
            'notify' => $rule['notify'] ?? FindingNotify::Digest,
        ], $rules));
    }

    /**
     * @return array{action?: FindingAction, notify?: FindingNotify}
     */
    private static function parse(string $code, mixed $rule): array
    {
        if (! in_array($code, self::CODES, true)) {
            throw new InvalidFindingRuleException(sprintf('Unknown finding code [%s] in content-security findings.', $code));
        }

        if (! is_array($rule)) {
            throw new InvalidFindingRuleException(sprintf('Finding rule [%s] must be an array with `action` and/or `notify`.', $code));
        }

        $parsed = [];

        if (array_key_exists('action', $rule)) {
            $parsed['action'] = FindingAction::tryFrom(is_string($rule['action']) ? $rule['action'] : '')
                ?? throw new InvalidFindingRuleException(sprintf(
                    'Finding rule [%s] has an unknown action. Use one of: %s.',
                    $code,
                    implode(', ', array_column(FindingAction::cases(), 'value')),
                ));

            if ($parsed['action'] === FindingAction::Allow && in_array($code, self::MANDATORY, true)) {
                throw new InvalidFindingRuleException(sprintf('Finding [%s] is a hard safety control and cannot be set to allow.', $code));
            }
        }

        if (array_key_exists('notify', $rule)) {
            $parsed['notify'] = FindingNotify::tryFrom(is_string($rule['notify']) ? $rule['notify'] : '')
                ?? throw new InvalidFindingRuleException(sprintf(
                    'Finding rule [%s] has an unknown notify mode. Use one of: %s.',
                    $code,
                    implode(', ', array_column(FindingNotify::cases(), 'value')),
                ));
        }

        $unknown = array_diff(array_keys($rule), ['action', 'notify']);

        if ($unknown !== []) {
            throw new InvalidFindingRuleException(sprintf('Finding rule [%s] has unknown keys: %s.', $code, implode(', ', $unknown)));
        }

        return $parsed;
    }

    /**
     * Tags each ruled threat with its `action`/`notify` (persisted with the
     * threat, read by the digest and the alert listener) and re-derives the
     * status of any check that carries an action.
     *
     * @param  list<CheckResult>  $checks
     * @return list<CheckResult>
     */
    public function apply(array $checks): array
    {
        if ($this->rules === []) {
            return $checks;
        }

        return array_map($this->applyTo(...), $checks);
    }

    private function applyTo(CheckResult $check): CheckResult
    {
        $threats = array_map(function (Threat $threat): Threat {
            $rule = $this->rules[$threat->name] ?? null;

            return $rule === null ? $threat : new Threat(
                $threat->name,
                $threat->level,
                $threat->source,
                $threat->description,
                [...$threat->metadata, 'action' => $rule['action']?->value, 'notify' => $rule['notify']->value],
            );
        }, $check->threats);

        $status = $check->status;

        // A failed or skipped check is never re-judged: fail-closed stays.
        if (! $check->skipped && in_array($status, [ScanStatus::Clean, ScanStatus::Suspicious, ScanStatus::Infected], true)) {
            $status = $this->statusFor($check);
        }

        return new CheckResult($check->check, $status, $threats, $check->metadata, $check->durationMs, $check->skipped, $check->error);
    }

    private function statusFor(CheckResult $check): ScanStatus
    {
        $ruled = array_filter($check->threats, fn (Threat $t): bool => ($this->rules[$t->name]['action'] ?? null) !== null);

        if ($ruled === []) {
            return $check->status;
        }

        // ponytail: any unruled finding keeps the check's original verdict, even if a ruled one was the
        // reason for it. Over-strict on mixed checks, never lenient.
        $status = count($ruled) < count($check->threats) ? $check->status : ScanStatus::Clean;

        foreach ($ruled as $threat) {
            if ($this->rules[$threat->name]['action'] !== FindingAction::Allow) {
                $status = $status->worst($threat->isAtLeast(ThreatLevel::High) ? ScanStatus::Infected : ScanStatus::Suspicious);
            }
        }

        return $status;
    }

    /**
     * The strongest action any finding requires: quarantine beats reject.
     * A finding without an action rule asks for the policy's on_threat, so
     * a `reject` rule never discards evidence another finding would keep.
     *
     * @param  list<Threat>  $threats
     */
    public function onThreat(array $threats, FailureAction $default): FailureAction
    {
        $required = [];

        foreach ($threats as $threat) {
            $required[] = match ($this->rules[$threat->name]['action'] ?? null) {
                FindingAction::Allow => null,
                FindingAction::Reject => FailureAction::Reject,
                FindingAction::Quarantine => FailureAction::Quarantine,
                null => $default,
            };
        }

        if (in_array(FailureAction::Quarantine, $required, true)) {
            return FailureAction::Quarantine;
        }

        return in_array(FailureAction::Reject, $required, true) ? FailureAction::Reject : $default;
    }
}
