<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\Html;

use LaravelPlus\ContentSecurity\Contracts\Sanitizer;
use Symfony\Component\HtmlSanitizer\HtmlSanitizer as SymfonyHtmlSanitizer;
use Symfony\Component\HtmlSanitizer\HtmlSanitizerConfig;

/**
 * Configurable HTML sanitization over symfony/html-sanitizer, which parses
 * the document with a real HTML5 parser and rebuilds it from an allowlist.
 *
 * Regex is not an option here and never will be. HTML is not a regular
 * language: `<img src=x onerror=alert(1)>`, `<<script>script>`, unclosed
 * attributes, entity-encoded payloads and mXSS all defeat pattern matching,
 * and every "sanitize with a regex" library in history has been bypassed.
 * Parse it, or do not claim to have sanitized it.
 */
final class HtmlSanitizer implements Sanitizer
{
    private ?SymfonyHtmlSanitizer $sanitizer = null;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(private readonly array $config) {}

    /**
     * @param  array<string, mixed>  $overrides
     */
    public static function fromConfig(array $overrides = []): self
    {
        /** @var array<string, mixed> $config */
        $config = (array) config('content-security.html', []);

        return new self([...$config, ...$overrides]);
    }

    public function sanitize(string $html): string
    {
        return $this->sanitizer()->sanitize($html);
    }

    /** Sanitizes as a document body fragment, e.g. an email template. */
    public function sanitizeFor(string $element, string $html): string
    {
        return $this->sanitizer()->sanitizeFor($element, $html);
    }

    private function sanitizer(): SymfonyHtmlSanitizer
    {
        return $this->sanitizer ??= new SymfonyHtmlSanitizer($this->buildConfig());
    }

    private function buildConfig(): HtmlSanitizerConfig
    {
        $config = new HtmlSanitizerConfig;

        /** @var list<string> $allowedTags */
        $allowedTags = (array) ($this->config['allowed_tags'] ?? []);
        /** @var array<string, list<string>> $allowedAttributes */
        $allowedAttributes = (array) ($this->config['allowed_attributes'] ?? []);

        /** @var list<string> $globalAttributes */
        $globalAttributes = (array) ($allowedAttributes['*'] ?? []);

        foreach ($allowedTags as $tag) {
            /** @var list<string> $attributes */
            $attributes = (array) ($allowedAttributes[$tag] ?? []);

            $config = $config->allowElement($tag, array_values(array_unique([
                ...$attributes,
                ...$globalAttributes,
            ])));
        }

        /** @var list<string> $schemes */
        $schemes = (array) ($this->config['allowed_schemes'] ?? ['http', 'https']);
        $config = $config
            ->allowLinkSchemes($schemes)
            ->allowMediaSchemes(array_values(array_filter(
                $schemes,
                static fn (string $scheme): bool => $scheme !== 'mailto',
            )));

        if ((bool) ($this->config['allow_relative_links'] ?? true)) {
            $config = $config->allowRelativeLinks();
        }

        if ((bool) ($this->config['allow_relative_medias'] ?? true)) {
            $config = $config->allowRelativeMedias();
        }

        /** @var list<string> $iframeHosts */
        $iframeHosts = (array) ($this->config['allowed_iframe_hosts'] ?? []);

        if ($iframeHosts !== []) {
            $config = $config
                ->allowElement('iframe', ['src', 'width', 'height', 'title', 'allow', 'allowfullscreen'])
                ->allowLinkHosts($iframeHosts)
                ->allowMediaHosts($iframeHosts);
        } else {
            $config = $config->blockElement('iframe');
        }

        $rel = $this->config['force_link_rel'] ?? null;

        if (is_string($rel) && $rel !== '') {
            // rel=noopener on every outbound link: without it, window.opener
            // hands the destination page control of the tab it came from.
            $config = $config->forceAttribute('a', 'rel', $rel);
        }

        $target = $this->config['force_link_target'] ?? null;

        if (is_string($target) && $target !== '') {
            $config = $config->forceAttribute('a', 'target', $target);
        }

        if (! (bool) ($this->config['allow_inline_styles'] ?? false)) {
            // The style attribute is an XSS surface in its own right
            // (url(javascript:…), expression(), and CSS that repositions an
            // element over a control the user meant to click).
            $config = $config->dropAttribute('style', '*');
        }

        $maxLength = (int) ($this->config['max_input_length'] ?? 1_000_000);

        if ($maxLength > 0) {
            $config = $config->withMaxInputLength($maxLength);
        }

        return $config;
    }
}
