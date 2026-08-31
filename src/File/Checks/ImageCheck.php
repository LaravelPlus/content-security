<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\File\Checks;

use LaravelPlus\ContentSecurity\Contracts\ImageInspector;
use LaravelPlus\ContentSecurity\Contracts\Sanitizer;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\Findings;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\Threat;
use LaravelPlus\ContentSecurity\Domain\Scan\ThreatLevel;

/**
 * SVG is handled apart from raster formats: it is not pixels, it is an XML
 * document that can carry script, and it is the one image type a browser
 * will execute.
 */
final class ImageCheck extends AbstractFileCheck
{
    /** SVGs are documents; a megabyte of XML is already pathological. */
    private const MAX_SVG_BYTES = 4 * 1024 * 1024;

    public function __construct(
        private readonly ImageInspector $inspector,
        private readonly Sanitizer $sanitizer,
    ) {}

    public function key(): string
    {
        return 'image';
    }

    public function label(): string
    {
        return 'Image validation';
    }

    public function appliesTo(FileReference $file, FilePolicy $policy): bool
    {
        return $this->inspector->handles($file);
    }

    protected function inspect(FileReference $file, FilePolicy $policy, ScanContext $context): Findings
    {
        if ($this->inspector->isVector($file)) {
            return $this->inspectSvg($file);
        }

        $findings = $this->inspector->inspect($file);

        if ($this->inspector->reencodes()) {
            $findings = $findings->withMetadata([
                'reencoded' => $this->inspector->reencode($file),
            ]);
        }

        return $findings;
    }

    private function inspectSvg(FileReference $file): Findings
    {
        if (! (bool) config('content-security.images.sanitize_svg', true)) {
            return Findings::none(['format' => 'svg', 'inspected' => false]);
        }

        if ($file->size() > self::MAX_SVG_BYTES) {
            return Findings::of(Threat::make(
                name: 'image.svg_too_large',
                level: ThreatLevel::Medium,
                source: $this->key(),
                description: 'The SVG is too large to inspect safely.',
            ), ['format' => 'svg', 'size' => $file->size()]);
        }

        $markup = $file->head(self::MAX_SVG_BYTES);
        $lowered = mb_strtolower($markup);
        $threats = [];

        foreach ([
            '<script' => ['image.svg_script', ThreatLevel::Critical, 'The SVG contains a <script> element.'],
            'javascript:' => ['image.svg_javascript_uri', ThreatLevel::Critical, 'The SVG contains a javascript: URI.'],
            '<foreignobject' => ['image.svg_foreign_object', ThreatLevel::High, 'The SVG contains a <foreignObject>, which can embed arbitrary HTML.'],
            '<!entity' => ['image.svg_entity', ThreatLevel::High, 'The SVG declares an XML entity (an XXE / billion-laughs vector).'],
            '<!doctype' => ['image.svg_doctype', ThreatLevel::Low, 'The SVG declares a DOCTYPE.'],
        ] as $needle => [$name, $level, $description]) {
            if (str_contains($lowered, $needle)) {
                $threats[] = Threat::make($name, $level, $this->key(), $description);
            }
        }

        // Inline event handlers: onload=, onclick= and the rest.
        if (preg_match('/\son[a-z]+\s*=/i', $markup) === 1) {
            $threats[] = Threat::make(
                name: 'image.svg_event_handler',
                level: ThreatLevel::Critical,
                source: $this->key(),
                description: 'The SVG carries inline event handler attributes.',
            );
        }

        return Findings::of($threats, [
            'format' => 'svg',
            'original_length' => mb_strlen($markup),
            // What a host would get by running this SVG through the
            // sanitizer before serving it. Offered as guidance; the file
            // itself is not modified here.
            'sanitized_length' => mb_strlen($this->sanitizer->sanitize($markup)),
        ]);
    }
}
