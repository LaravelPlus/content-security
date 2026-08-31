<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Pipeline;

use Illuminate\Contracts\Container\Container;
use InvalidArgumentException;
use LaravelPlus\ContentSecurity\Contracts\FileCheck;
use LaravelPlus\ContentSecurity\Contracts\SecurityCheck;
use LaravelPlus\ContentSecurity\Contracts\TextCheck;

/**
 * The ordered list of checks each pipeline runs, and the seam a host uses to
 * add its own without touching package source.
 *
 * Checks are held as class names and resolved from the container per scan,
 * so a custom check gets normal constructor injection and nothing is
 * instantiated at registration time (which would run before the host's own
 * bindings exist).
 */
final class CheckRegistry
{
    /** @var list<class-string<FileCheck>> */
    private array $fileChecks = [];

    /** @var list<class-string<TextCheck>> */
    private array $textChecks = [];

    public function __construct(private readonly Container $container) {}

    /**
     * @param  list<class-string<FileCheck>>  $checks
     */
    public function setFileChecks(array $checks): void
    {
        $this->fileChecks = array_values($checks);
    }

    /**
     * @param  list<class-string<TextCheck>>  $checks
     */
    public function setTextChecks(array $checks): void
    {
        $this->textChecks = array_values($checks);
    }

    /**
     * Appends a file check, or places it next to an existing one.
     *
     * @param  class-string<FileCheck>  $check
     * @param  class-string<FileCheck>|null  $before
     * @param  class-string<FileCheck>|null  $after
     */
    public function addFileCheck(string $check, ?string $before = null, ?string $after = null): void
    {
        $this->fileChecks = $this->insert($this->fileChecks, $check, $before, $after);
    }

    /**
     * @param  class-string<TextCheck>  $check
     * @param  class-string<TextCheck>|null  $before
     * @param  class-string<TextCheck>|null  $after
     */
    public function addTextCheck(string $check, ?string $before = null, ?string $after = null): void
    {
        $this->textChecks = $this->insert($this->textChecks, $check, $before, $after);
    }

    /**
     * Removes a shipped check. Rarely the right answer — prefer switching it
     * off in the policy, which leaves a record that it was switched off.
     *
     * @param  class-string<SecurityCheck>  $check
     */
    public function remove(string $check): void
    {
        $this->fileChecks = array_values(array_filter(
            $this->fileChecks,
            static fn (string $registered): bool => $registered !== $check,
        ));

        $this->textChecks = array_values(array_filter(
            $this->textChecks,
            static fn (string $registered): bool => $registered !== $check,
        ));
    }

    /**
     * @return list<FileCheck>
     */
    public function fileChecks(): array
    {
        /** @var list<FileCheck> $checks */
        $checks = array_map(
            fn (string $check): object => $this->container->make($check),
            $this->fileChecks,
        );

        return $checks;
    }

    /**
     * @return list<TextCheck>
     */
    public function textChecks(): array
    {
        /** @var list<TextCheck> $checks */
        $checks = array_map(
            fn (string $check): object => $this->container->make($check),
            $this->textChecks,
        );

        return $checks;
    }

    /**
     * @return list<class-string<FileCheck>>
     */
    public function registeredFileChecks(): array
    {
        return $this->fileChecks;
    }

    /**
     * @return list<class-string<TextCheck>>
     */
    public function registeredTextChecks(): array
    {
        return $this->textChecks;
    }

    /**
     * @template TCheck of SecurityCheck
     *
     * @param  list<class-string<TCheck>>  $checks
     * @param  class-string<TCheck>  $check
     * @param  class-string<TCheck>|null  $before
     * @param  class-string<TCheck>|null  $after
     * @return list<class-string<TCheck>>
     */
    private function insert(array $checks, string $check, ?string $before, ?string $after): array
    {
        if ($before !== null && $after !== null) {
            throw new InvalidArgumentException('Give a check either $before or $after, not both.');
        }

        $checks = array_values(array_filter(
            $checks,
            static fn (string $registered): bool => $registered !== $check,
        ));

        $anchor = $before ?? $after;

        if ($anchor === null) {
            $checks[] = $check;

            return $checks;
        }

        $position = array_search($anchor, $checks, true);

        if ($position === false) {
            // An unknown anchor appends rather than throws: a host that
            // removed the shipped check it anchored against should not get
            // a fatal error at boot for it.
            $checks[] = $check;

            return $checks;
        }

        $offset = $before !== null ? $position : $position + 1;

        return array_values([
            ...array_slice($checks, 0, $offset),
            $check,
            ...array_slice($checks, $offset),
        ]);
    }
}
