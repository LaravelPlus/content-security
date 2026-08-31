<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Checks;

use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;
use LaravelPlus\ContentSecurity\Exceptions\InvalidFileException;
use LaravelPlus\ContentSecurity\Support\MimeTypes;

/**
 * Compares three claims about what the file is — its extension, the
 * browser's Content-Type, and what libmagic reads out of the bytes. Only the
 * last is evidence; the first two are recorded so a mismatch is visible.
 */
final class MimeCheck extends AbstractFileCheck
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

    protected function inspect(FileReference $file, FilePolicy $policy, ScanContext $context): Findings
    {
        $detected = $this->mimeTypes->detect($file);

        $metadata = [
            'declared_mime' => $file->declaredMime,
            'detected_mime' => $detected,
            'extension' => $file->extension(),
        ];

        if ($detected === null) {
            // Thrown, not returned: the base class turns it into a FAILED
            // check, which is the fail-closed outcome. "We could not tell
            // what this is" must never read as a pass.
            throw InvalidFileException::unreadable($file->originalName);
        }

        $threats = [];

        if ($policy->hasMimeAllowlist() && ! $policy->allowsMime($detected)) {
            $threats[] = Threat::make(
                name: 'file.mime_not_allowed',
                level: ThreatLevel::Medium,
                source: $this->key(),
                description: sprintf('Detected type %s is not on the policy allowlist.', $detected),
                metadata: ['detected_mime' => $detected],
            );
        }

        if (! $this->mimeTypes->matchesExtension($file->extension(), $detected)) {
            $threats[] = Threat::make(
                name: 'file.mime_extension_mismatch',
                // Deception, not preference: the bytes are one thing and the
                // name says another.
                level: ThreatLevel::High,
                source: $this->key(),
                description: sprintf('The file is a %s but is named .%s.', $detected, $file->extension()),
                metadata: [
                    'detected_mime' => $detected,
                    'extension' => $file->extension(),
                    'expected' => $this->mimeTypes->expectedFor($file->extension()),
                ],
            );
        }

        if (! $this->mimeTypes->declaredMatchesDetected($file->declaredMime, $detected)) {
            // Informational: browsers get this wrong unprompted, and the
            // header is uploader-controlled either way.
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

        return Findings::of($threats, $metadata);
    }
}
