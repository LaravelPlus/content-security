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
use LaravelPlus\ContentSecurity\File\Images\ImageInspector;
use LaravelPlus\ContentSecurity\Text\Html\HtmlSanitizer;
use Throwable;

/**
 * SVG is handled apart from raster formats: it is not pixels, it is an XML
 * document that can carry script, and it is the one image type a browser
 * will happily execute.
 */
final class ImageCheck implements FileCheck
{
    public function __construct(
        private readonly ImageInspector $inspector,
        private readonly HtmlSanitizer $sanitizer,
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
        return $this->inspector->isImage($file);
    }

    public function check(FileReference $file, FilePolicy $policy, ScanContext $context): CheckResult
    {
        try {
            if ($this->inspector->looksLikeSvg($file)) {
                return $this->checkSvg($file);
            }

            ['threats' => $threats, 'metadata' => $metadata] = $this->inspector->inspect($file);

            if ($this->inspector->reencodes()) {
                $metadata['reencoded'] = $this->inspector->reencode($file);
            }
        } catch (Throwable $e) {
            return CheckResult::failed($this->key(), $e->getMessage());
        }

        if ($threats === []) {
            return CheckResult::passed($this->key(), $metadata);
        }

        $blocking = array_filter(
            $threats,
            static fn (Threat $threat): bool => $threat->isAtLeast(ThreatLevel::High),
        );

        return $blocking !== []
            ? CheckResult::infected($this->key(), array_values($threats), $metadata)
            : CheckResult::suspicious($this->key(), array_values($threats), $metadata);
    }

    private function checkSvg(FileReference $file): CheckResult
    {
        if (! (bool) config('content-security.images.sanitize_svg', true)) {
            return CheckResult::skipped($this->key(), 'SVG inspection is disabled.', ['format' => 'svg']);
        }

        // SVGs are documents, not photographs — a megabyte of XML is already
        // pathological, so reading it whole is bounded and safe.
        $limit = 4 * 1024 * 1024;

        if ($file->size() > $limit) {
            return CheckResult::suspicious($this->key(), Threat::make(
                name: 'image.svg_too_large',
                level: ThreatLevel::Medium,
                source: $this->key(),
                description: 'The SVG is too large to inspect safely.',
            ), ['format' => 'svg', 'size' => $file->size()]);
        }

        $markup = $file->head($limit);
        $lowered = mb_strtolower($markup);

        $findings = [];

        foreach ([
            '<script' => ['image.svg_script', ThreatLevel::Critical, 'The SVG contains a <script> element.'],
            'javascript:' => ['image.svg_javascript_uri', ThreatLevel::Critical, 'The SVG contains a javascript: URI.'],
            '<foreignobject' => ['image.svg_foreign_object', ThreatLevel::High, 'The SVG contains a <foreignObject>, which can embed arbitrary HTML.'],
            '<!entity' => ['image.svg_entity', ThreatLevel::High, 'The SVG declares an XML entity (XXE / billion-laughs vector).'],
            '<!doctype' => ['image.svg_doctype', ThreatLevel::Low, 'The SVG declares a DOCTYPE.'],
        ] as $needle => [$name, $level, $description]) {
            if (str_contains($lowered, $needle)) {
                $findings[] = Threat::make($name, $level, $this->key(), $description);
            }
        }

        // Inline event handlers: onload=, onclick=, and the rest.
        if (preg_match('/\son[a-z]+\s*=/i', $markup) === 1) {
            $findings[] = Threat::make(
                name: 'image.svg_event_handler',
                level: ThreatLevel::Critical,
                source: $this->key(),
                description: 'The SVG carries inline event handler attributes.',
            );
        }

        $metadata = [
            'format' => 'svg',
            // What a host would get if it ran the SVG through the sanitizer
            // before serving it. Offered as guidance, not applied here.
            'sanitized_length' => mb_strlen($this->sanitizer->sanitize($markup)),
            'original_length' => mb_strlen($markup),
        ];

        if ($findings === []) {
            return CheckResult::passed($this->key(), $metadata);
        }

        $blocking = array_filter(
            $findings,
            static fn (Threat $threat): bool => $threat->isAtLeast(ThreatLevel::High),
        );

        return $blocking !== []
            ? CheckResult::infected($this->key(), array_values($findings), $metadata)
            : CheckResult::suspicious($this->key(), array_values($findings), $metadata);
    }
}
