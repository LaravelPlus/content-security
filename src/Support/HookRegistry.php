<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Support;

use Closure;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanContext;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;

/**
 * Where a host application reaches into the middle of a scan.
 *
 * Events already cover "tell me what happened". These hooks cover the things
 * events cannot: changing the context before a scan runs, changing the
 * verdict after it, and resolving policies from somewhere other than the
 * config file (a database table, a per-tenant setting).
 *
 * Held on the ContentSecurity singleton rather than in statics, so a test
 * gets a clean registry with the container and nothing leaks between them.
 */
final class HookRegistry
{
    /** @var list<Closure(ScanContext): ScanContext> */
    private array $before = [];

    /** @var list<Closure(ScanResult, ScanContext): ScanResult> */
    private array $after = [];

    /** @var (Closure(string): FilePolicy)|null */
    private ?Closure $filePolicyResolver = null;

    /** @var (Closure(string): TextPolicy)|null */
    private ?Closure $textPolicyResolver = null;

    /** @var (Closure(mixed): bool)|null */
    private ?Closure $authorization = null;

    /**
     * Runs before any check. Return the context — amended or as given — to
     * attach tenant ids, request ids, or anything the audit row should carry.
     *
     * @param  Closure(ScanContext): ScanContext  $callback
     */
    public function before(Closure $callback): void
    {
        $this->before[] = $callback;
    }

    /**
     * Runs after the pipeline, before persistence and events. The returned
     * result is the one everything downstream sees, so this can downgrade a
     * finding the application knows to be a false positive — deliberately,
     * and in one auditable place.
     *
     * @param  Closure(ScanResult, ScanContext): ScanResult  $callback
     */
    public function after(Closure $callback): void
    {
        $this->after[] = $callback;
    }

    /** @param Closure(string): FilePolicy $resolver */
    public function resolveFilePolicyUsing(Closure $resolver): void
    {
        $this->filePolicyResolver = $resolver;
    }

    /** @param Closure(string): TextPolicy $resolver */
    public function resolveTextPolicyUsing(Closure $resolver): void
    {
        $this->textPolicyResolver = $resolver;
    }

    /** @param Closure(mixed): bool $callback */
    public function authorizeUsing(Closure $callback): void
    {
        $this->authorization = $callback;
    }

    public function runBefore(ScanContext $context): ScanContext
    {
        foreach ($this->before as $callback) {
            $context = $callback($context);
        }

        return $context;
    }

    public function runAfter(ScanResult $result, ScanContext $context): ScanResult
    {
        foreach ($this->after as $callback) {
            $result = $callback($result, $context);
        }

        return $result;
    }

    public function filePolicy(string $name): FilePolicy
    {
        return $this->filePolicyResolver === null
            ? FilePolicy::named($name)
            : ($this->filePolicyResolver)($name);
    }

    public function textPolicy(string $name): TextPolicy
    {
        return $this->textPolicyResolver === null
            ? TextPolicy::named($name)
            : ($this->textPolicyResolver)($name);
    }

    public function hasAuthorization(): bool
    {
        return $this->authorization !== null;
    }

    public function authorize(mixed $user): bool
    {
        return $this->authorization !== null && ($this->authorization)($user);
    }
}
