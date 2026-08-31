<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Exceptions;

use RuntimeException;

/**
 * Root of every exception the package throws, so a host can catch the whole
 * package with one clause.
 */
abstract class ContentSecurityException extends RuntimeException {}
