<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Text\Html;

use Symfony\Component\HtmlSanitizer\HtmlSanitizerConfig;
use Symfony\Component\HtmlSanitizer\TextSanitizer\UrlSanitizer;
use Symfony\Component\HtmlSanitizer\Visitor\AttributeSanitizer\AttributeSanitizerInterface;

/**
 * Host allowlist for `<iframe src>` alone. symfony/html-sanitizer only has
 * global link and media host lists, which would also restrict every `<a>`
 * and `<img>`; this keeps embeds on their own list. Runs after Symfony's
 * own URL sanitizer, so the scheme checks still apply.
 */
final readonly class IframeSrcSanitizer implements AttributeSanitizerInterface
{
    /** @param  list<string>  $hosts */
    public function __construct(private array $hosts) {}

    public function getSupportedElements(): array
    {
        return ['iframe'];
    }

    public function getSupportedAttributes(): array
    {
        return ['src'];
    }

    public function sanitizeAttribute(string $element, string $attribute, string $value, HtmlSanitizerConfig $config): ?string
    {
        // Relative embeds are refused: an allowlisted host must be named.
        return UrlSanitizer::sanitize($value, $config->getAllowedMediaSchemes(), $config->getForceHttpsUrls(), $this->hosts, false);
    }
}
