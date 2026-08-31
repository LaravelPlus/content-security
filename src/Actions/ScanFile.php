<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FailureAction;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanStatus;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanType;
use LaravelPlus\ContentSecurity\Events\ScanCompleted;
use LaravelPlus\ContentSecurity\Events\ScanFailed;
use LaravelPlus\ContentSecurity\Events\ScanStarted;
use LaravelPlus\ContentSecurity\Events\ThreatDetected;
use LaravelPlus\ContentSecurity\File\FileSecurityPipeline;
use LaravelPlus\ContentSecurity\Pipeline\CheckRegistry;
use LaravelPlus\ContentSecurity\Pipeline\PipelineRunner;
use LaravelPlus\ContentSecurity\Support\HookRegistry;
use Throwable;

/**
 * One file scan, end to end: policy, hooks, pipeline, persistence, events,
 * and quarantine.
 *
 * The order is deliberate. The audit row is opened *before* the pipeline
 * runs, so a scan that dies mid-way leaves evidence that it was attempted
 * rather than no trace at all.
 */
final readonly class ScanFile
{
    public function __construct(
        private CheckRegistry $checks,
        private PipelineRunner $runner,
        private ScanRepository $repository,
        private Dispatcher $events,
        private HookRegistry $hooks,
        private QuarantineFile $quarantine,
    ) {}

    public function handle(
        FileReference $file,
        ?string $policyName = null,
        ?ScanId $scanId = null,
        bool $quarantineOnThreat = true,
    ): ScanResult {
        $policyName ??= (string) config('content-security.files.default_policy', 'default');
        $policy = $this->hooks->filePolicy($policyName);

        $context = $this->hooks->runBefore(new ScanContext(
            scanId: $scanId ?? ScanId::generate(),
            type: ScanType::File,
            policy: $policy->name(),
        ));

        $this->repository->start($context, $file);
        $this->events->dispatch(new ScanStarted($context));
        $this->repository->markScanning($context->scanId);

        try {
            $pipeline = new FileSecurityPipeline($this->checks->fileChecks(), $this->runner);
            $result = $pipeline->run($file, $policy, $context);
        } catch (Throwable $e) {
            // The pipeline already contains a per-check safety net; this
            // catches the rest (a policy that cannot load, a disk that
            // disappeared) so a scan never escapes as an unhandled error.
            $result = ScanResult::failure($context, $e->getMessage());
            $result = $this->hooks->runAfter($result, $context);

            $this->repository->complete($result);
            $this->events->dispatch(new ScanFailed($result, $context, $e->getMessage()));

            return $result;
        }

        $result = $this->hooks->runAfter($result, $context);

        if ($quarantineOnThreat && $this->shouldQuarantine($result, $policy->onThreat)) {
            $result = $this->quarantineFile($file, $context->scanId, $result);
        }

        $this->repository->complete($result);
        $this->dispatchOutcome($result, $context);

        return $result;
    }

    private function shouldQuarantine(ScanResult $result, FailureAction $onThreat): bool
    {
        if ($onThreat !== FailureAction::Quarantine) {
            return false;
        }

        // A failed scan is quarantined too. The file is unproven, not
        // proven bad, and throwing away the one artefact an operator needs
        // to work out why the scanner broke is the wrong instinct.
        return ! $result->isClean();
    }

    private function quarantineFile(FileReference $file, ScanId $scanId, ScanResult $result): ScanResult
    {
        try {
            $path = $this->quarantine->handle($file, $scanId, $result);

            return $result
                ->withStatus(ScanStatus::Quarantined)
                ->withMetadata(['quarantined' => true, 'quarantine_path' => $path]);
        } catch (Throwable $e) {
            // Quarantine failing does not make the file clean. The verdict
            // stands; only the evidence was lost.
            return $result->withMetadata([
                'quarantined' => false,
                'quarantine_error' => $e->getMessage(),
            ]);
        }
    }

    private function dispatchOutcome(ScanResult $result, ScanContext $context): void
    {
        foreach ($result->threats() as $threat) {
            $this->events->dispatch(new ThreatDetected($threat, $result, $context));
        }

        if ($result->failed()) {
            $error = $result->metadata()['error'] ?? null;

            $this->events->dispatch(new ScanFailed(
                $result,
                $context,
                is_string($error) ? $error : 'A security check could not be completed.',
            ));
        }

        $this->events->dispatch(new ScanCompleted($result, $context));
    }
}
