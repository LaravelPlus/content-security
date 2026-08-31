<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Checks;

use LaravelPlus\ContentSecurity\Contracts\FileCheck;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\CheckResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use LaravelPlus\ContentSecurity\Support\MimeTypes;

/**
 * Compares three claims about what the file is — the extension, the browser's
 * Content-Type, and what libmagic reads out of the bytes. Only the last one
 * is evidence; the first two are recorded so a mismatch is visible.
 */
final class MimeCheck implements FileCheck
{
    public function __construct(private readonly MimeTypes $mimeTypes) {}

    public function key(): string
    {
        return 'mime';
    }

    public function label(): string
    {
        return 'MIME type';
    }

    public function appliesTo(FileReference $file, FilePolicy $policy): bool
    {
        return true;
    }

    public function check(FileReference $file, FilePolicy $policy, ScanContext $context): CheckResult
    {
        $detected = $this->mimeTypes->detect($file);

        $metadata = [
            'declared_mime' => $file->declaredMime,
            'detected_mime' => $detected,
            'extension' => $file->extension(),
        ];

        if ($detected === null) {
            return CheckResult::failed($this->key(), 'The file type could not be determined.', $metadata);
        }

        $threats = [];

        if ($policy->hasMimeAllowlist() && ! $policy->allowsMime($detected)) {
            $threats[] = Threat::make(
                name: 'file.mime_not_allowed',
                level: ThreatLevel::High,
                source: $this->key(),
                description: sprintf('Detected type %s is not on the policy allowlist.', $detected),
                metadata: ['detected_mime' => $detected],
            );
        }

        if (! $this->mimeTypes->matchesExtension($file->extension(), $detected)) {
            $threats[] = Threat::make(
                name: 'file.mime_extension_mismatch',
                level: ThreatLevel::High,
                source: $this->key(),
                description: sprintf(
                    'The file is a %s but is named .%s.',
                    $detected,
                    $file->extension(),
                ),
                metadata: [
                    'detected_mime' => $detected,
                    'extension' => $file->extension(),
                    'expected' => $this->mimeTypes->expectedFor($file->extension()),
                ],
            );
        }

        if (! $this->mimeTypes->declaredMatchesDetected($file->declaredMime, $detected)) {
            // Informational: browsers get this wrong on their own, and the
            // header is attacker-controlled either way.
            $threats[] = Threat::make(
                name: 'file.declared_mime_mismatch',
                level: ThreatLevel::Info,
                source: $this->key(),
                description: sprintf(
                    'The upload declared %s but the bytes are %s.',
                    (string) $file->declaredMime,
                    $detected,
                ),
                metadata: ['declared_mime' => $file->declaredMime, 'detected_mime' => $detected],
            );
        }

        if ($threats === []) {
            return CheckResult::passed($this->key(), $metadata);
        }

        $hasBlocking = array_filter(
            $threats,
            static fn (Threat $threat): bool => $threat->isAtLeast(ThreatLevel::High),
        );

        return $hasBlocking !== []
            ? CheckResult::infected($this->key(), array_values($threats), $metadata)
            : CheckResult::suspicious($this->key(), array_values($threats), $metadata);
    }
}
