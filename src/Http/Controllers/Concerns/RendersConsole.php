<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Controllers\Concerns;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response as InertiaResponse;

/**
 * Every console page renders the same way, and every one is addressable as
 * JSON — an operator debugging a number wants the figures, not the page.
 */
trait RendersConsole
{
    /**
     * @param  array<string, mixed>  $props
     */
    protected function render(Request $request, string $page, array $props): InertiaResponse|JsonResponse
    {
        if ($request->wantsJson() && ! $request->headers->has('X-Inertia')) {
            return response()->json($props);
        }

        return Inertia::render('admin/content-security/'.$page, $props);
    }

    protected function perPage(Request $request): int
    {
        $default = (int) config('content-security.admin.per_page', 25);
        $requested = $request->integer('per_page', $default);

        // Bounded: an unbounded per_page is a denial-of-service parameter
        // dressed up as a convenience.
        return max(10, min(100, $requested === 0 ? $default : $requested));
    }
}
