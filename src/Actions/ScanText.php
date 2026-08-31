<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Actions;

use Illuminate\Contracts\Events\Dispatcher;
use LaravelPlus\ContentSecurity\Contracts\ScanRepository;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanType;
use LaravelPlus\ContentSecurity\Events\ScanCompleted;
use LaravelPlus\ContentSecurity\Events\ScanFailed;
use LaravelPlus\ContentSecurity\Events\ScanStarted;
use LaravelPlus\ContentSecurity\Events\ThreatDetected;
use LaravelPlus\ContentSecurity\Pipeline\CheckRegistry;
use LaravelPlus\ContentSecurity\Pipeline\PipelineRunner;
use LaravelPlus\ContentSecurity\Support\HookRegistry;
use LaravelPlus\ContentSecurity\Text\TextSecurityPipeline;
use Throwable;

/**
 * One text scan. Nothing here quarantines — text has no file to move, and
 * the audit row deliberately keeps a hash rather than the input.
 */
final readonly class ScanText
{
    public function __construct(
        private CheckRegistry $checks,
        private PipelineRunner $runner,
        private ScanRepository $repository,
        private Dispatcher $events,
        private HookRegistry $hooks,
    ) {}

    public function handle(
        string $text,
        ?string $policyName = null,
        ScanType $type = ScanType::Text,
        ?ScanId $scanId = null,
    ): ScanResult {
        $policyName ??= (string) config('content-security.text.default_policy', 'default');
        $policy = $this->hooks->textPolicy($policyName);

        $context = $this->hooks->runBefore(new ScanContext(
            scanId: $scanId ?? ScanId::generate(),
            type: $type,
            policy: $policy->name(),
        ));

        $this->repository->start($context);
        $this->events->dispatch(new ScanStarted($context));

        try {
            $pipeline = new TextSecurityPipeline($this->checks->textChecks(), $this->runner);
            $result = $pipeline->run($text, $policy, $context);
        } catch (Throwable $e) {
            $result = $this->hooks->runAfter(ScanResult::failure($context, $e->getMessage()), $context);

            $this->repository->complete($result);
            $this->events->dispatch(new ScanFailed($result, $context, $e->getMessage()));

            return $result;
        }

        $result = $this->hooks->runAfter($result, $context)
            ->withMetadata($this->sample($text));

        $this->repository->complete($result);

        foreach ($result->threats() as $threat) {
            $this->events->dispatch(new ThreatDetected($threat, $result, $context));
        }

        if ($result->failed()) {
            $this->events->dispatch(new ScanFailed($result, $context, 'A text check could not be completed.'));
        }

        $this->events->dispatch(new ScanCompleted($result, $context));

        return $result;
    }

    /**
     * A short excerpt, and only when the host has asked for one. The default
     * is off: an audit table that quietly accumulates everything users typed
     * is a data-protection problem wearing a security badge.
     *
     * @return array<string, scalar|null>
     */
    private function sample(string $text): array
    {
        if (! (bool) config('content-security.persistence.store_text_samples', false)) {
            return [];
        }

        $length = (int) config('content-security.persistence.text_sample_length', 200);

        return ['content_sample' => mb_substr($text, 0, $length)];
    }
}
