<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Inertia\Response as InertiaResponse;
use LaravelPlus\ContentSecurity\ContentSecurity;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Http\Controllers\Concerns\RendersConsole;
use LaravelPlus\ContentSecurity\Http\Resources\ScannerHealthResource;
use LaravelPlus\ContentSecurity\Models\SecurityScan;
use Throwable;

final class HealthController extends Controller
{
    use RendersConsole;

    public function index(Request $request, ContentSecurity $security): InertiaResponse|JsonResponse
    {
        return $this->render($request, 'Health/Index', [
            'scanners' => ScannerHealthResource::collection($security->health())->resolve(),
            'lastScanAt' => SecurityScan::query()->latest('created_at')->value('created_at')?->toIso8601String(),
            'pipeline' => [
                'file' => array_map(
                    static fn (object $check): array => ['key' => $check->key(), 'label' => $check->label()],
                    $security->checks()->fileChecks(),
                ),
                'text' => array_map(
                    static fn (object $check): array => ['key' => $check->key(), 'label' => $check->label()],
                    $security->checks()->textChecks(),
                ),
            ],
            'extensions' => [
                'fileinfo' => extension_loaded('fileinfo'),
                'zip' => extension_loaded('zip'),
                'gd' => extension_loaded('gd'),
            ],
        ]);
    }

    /**
     * Sends the EICAR test string to the configured engine.
     *
     * EICAR is the industry's standard harmless test file: 68 printable
     * ASCII characters that every scanner is required to flag, and which do
     * nothing whatsoever if executed. It proves the engine is reachable and
     * actually matching, without putting real malware on the machine.
     */
    public function test(Request $request, ContentSecurity $security): RedirectResponse
    {
        $eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
        $temp = tempnam(sys_get_temp_dir(), 'cs-eicar-');

        if ($temp === false) {
            return back()->with('error', 'Could not create a temporary file for the test.');
        }

        try {
            file_put_contents($temp, $eicar);

            $result = $security->scanner()->scan(FileReference::fromPath($temp, 'eicar.com'));

            return back()->with(
                $result->status->value === 'infected' ? 'success' : 'error',
                $result->status->value === 'infected'
                    ? 'The engine detected the EICAR test file. Scanning is working.'
                    : sprintf('The engine did NOT flag the EICAR test file (reported: %s). Scanning is not working.', $result->status->value),
            );
        } catch (Throwable $e) {
            return back()->with('error', 'The scanner test failed: '.$e->getMessage());
        } finally {
            @unlink($temp);
        }
    }
}
