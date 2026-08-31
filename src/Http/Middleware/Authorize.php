<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use LaravelPlus\ContentSecurity\ContentSecurity;
use Symfony\Component\HttpFoundation\Response;

/**
 * Gate for the security console.
 *
 * Denies with 404, not 403. The console lists what has been uploaded, what
 * was caught and what sits in quarantine; confirming to an unauthorised
 * visitor that such a page exists at this URL is itself information they
 * should not have.
 */
final class Authorize
{
    public function __construct(private readonly ContentSecurity $security) {}

    public function handle(Request $request, Closure $next): Response
    {
        abort_unless($this->security->authorize($request->user()), 404);

        return $next($request);
    }
}
