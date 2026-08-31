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

/**
 * Looks for executable and script signatures in the file header, whatever
 * the extension or the MIME type says.
 *
 * This is not malware detection — it recognises *formats*, not payloads. A
 * Windows binary renamed to .jpg is caught here; a novel trojan is not. That
 * is what the malware engine is for.
 */
final class MagicBytesCheck implements FileCheck
{
    /**
     * Signature => [label, threat level]. Offsets are all zero except where
     * noted in `check()`.
     *
     * @var array<string, array{0: string, 1: ThreatLevel}>
     */
    private const SIGNATURES = [
        'MZ' => ['DOS/Windows executable', ThreatLevel::Critical],
        "\x7fELF" => ['ELF executable', ThreatLevel::Critical],
        // CAFEBABE is shared by Java class files and Mach-O fat binaries.
        // Both are executable code; the ambiguity does not change the verdict.
        "\xca\xfe\xba\xbe" => ['Java class / Mach-O fat binary', ThreatLevel::Critical],
        "\xcf\xfa\xed\xfe" => ['Mach-O 64-bit executable', ThreatLevel::Critical],
        "\xce\xfa\xed\xfe" => ['Mach-O 32-bit executable', ThreatLevel::Critical],
        '#!' => ['Shebang script', ThreatLevel::High],
        '<?php' => ['PHP source', ThreatLevel::Critical],
        '<?=' => ['PHP short echo tag', ThreatLevel::Critical],
    ];

    public function key(): string
    {
        return 'magic_bytes';
    }

    public function label(): string
    {
        return 'Magic bytes';
    }

    public function appliesTo(FileReference $file, FilePolicy $policy): bool
    {
        return true;
    }

    public function check(FileReference $file, FilePolicy $policy, ScanContext $context): CheckResult
    {
        $head = $file->head(8192);

        if ($head === '') {
            return CheckResult::skipped($this->key(), 'The file has no readable header.');
        }

        foreach (self::SIGNATURES as $signature => [$label, $level]) {
            if (str_starts_with($head, $signature)) {
                return CheckResult::infected($this->key(), Threat::make(
                    name: 'file.executable_content',
                    level: $level,
                    source: $this->key(),
                    description: sprintf('The file begins with a %s signature.', $label),
                    metadata: ['format' => $label],
                ), ['signature' => $label]);
            }
        }

        // A PHP tag *anywhere* in the header of something claiming to be an
        // image: the polyglot upload that survives getimagesize().
        if (preg_match('/<\?php|<\?=/i', $head) === 1) {
            return CheckResult::infected($this->key(), Threat::make(
                name: 'file.embedded_php',
                level: ThreatLevel::Critical,
                source: $this->key(),
                description: 'PHP opening tags were found inside the file header.',
            ), ['signature' => 'embedded PHP']);
        }

        return CheckResult::passed($this->key(), ['header_bytes' => strlen($head)]);
    }
}
