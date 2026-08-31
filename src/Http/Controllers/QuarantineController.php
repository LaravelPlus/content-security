<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Inertia\Response as InertiaResponse;
use LaravelPlus\ContentSecurity\Actions\ReleaseQuarantinedFile;
use LaravelPlus\ContentSecurity\Exceptions\QuarantineException;
use LaravelPlus\ContentSecurity\Http\Controllers\Concerns\RendersConsole;
use LaravelPlus\ContentSecurity\Http\Requests\ReleaseQuarantineRequest;
use LaravelPlus\ContentSecurity\Http\Resources\ScanResource;
use LaravelPlus\ContentSecurity\Models\SecurityScan;

final class QuarantineController extends Controller
{
    use RendersConsole;

    public function index(Request $request): InertiaResponse|JsonResponse
    {
        $items = SecurityScan::query()
            ->with('threats')
            ->quarantined()
            ->latest('created_at')
            ->paginate($this->perPage($request))
            ->withQueryString();

        return $this->render($request, 'Quarantine/Index', [
            'items' => ScanResource::collection($items)->response()->getData(true),
            'retentionDays' => (int) config('content-security.storage.retention_days', 30),
        ]);
    }

    public function rescan(Request $request, SecurityScan $scan, ReleaseQuarantinedFile $action): RedirectResponse
    {
        try {
            $action->rescan($scan);
        } catch (QuarantineException $e) {
            return back()->with('error', $e->getMessage());
        }

        return back()->with('success', 'The file was rescanned. The verdict has been updated.');
    }

    public function release(
        ReleaseQuarantineRequest $request,
        SecurityScan $scan,
        ReleaseQuarantinedFile $action,
    ): RedirectResponse {
        try {
            $action->handle(
                scan: $scan,
                targetDisk: $request->string('disk')->value(),
                targetPath: $request->string('path')->value(),
                actorId: $request->user()?->getAuthIdentifier(),
                override: $request->boolean('override'),
            );
        } catch (QuarantineException $e) {
            return back()->with('error', $e->getMessage());
        }

        return back()->with(
            'success',
            $request->boolean('override')
                ? 'Released with an override. The action has been recorded in the audit log.'
                : 'Released after a clean rescan.',
        );
    }

    public function destroy(Request $request, SecurityScan $scan, ReleaseQuarantinedFile $action): RedirectResponse
    {
        try {
            $action->delete($scan, $request->user()?->getAuthIdentifier());
        } catch (QuarantineException $e) {
            return back()->with('error', $e->getMessage());
        }

        // The scan row survives on purpose: that a file was quarantined is
        // the part of the record worth keeping after the file is gone.
        return back()->with('success', 'The quarantined file was permanently deleted. Its scan record was kept.');
    }
}
