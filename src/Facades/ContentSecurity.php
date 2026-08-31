<?php

declare(strict_types=1);

namespace LaravelPlus\ContentSecurity\Facades;

use Closure;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Facade;
use LaravelPlus\ContentSecurity\ContentSecurity as ContentSecurityManager;
use LaravelPlus\ContentSecurity\Contracts\MalwareScanner;
use LaravelPlus\ContentSecurity\Domain\File\FileReference;
use LaravelPlus\ContentSecurity\Domain\Policy\FilePolicy;
use LaravelPlus\ContentSecurity\Domain\Policy\TextPolicy;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanId;
use LaravelPlus\ContentSecurity\Domain\Scan\ScanResult;
use LaravelPlus\ContentSecurity\Pipeline\CheckRegistry;
use LaravelPlus\ContentSecurity\Support\HookRegistry;
use LaravelPlus\ContentSecurity\Support\ScannerHealth;

/**
 * @method static ScanResult scanFile(UploadedFile|FileReference|string $file, FilePolicy|string|null $policy = null)
 * @method static ScanResult scanDisk(string $disk, string $path, FilePolicy|string|null $policy = null)
 * @method static ScanResult scanFileOrFail(UploadedFile|FileReference|string $file, FilePolicy|string|null $policy = null)
 * @method static ScanResult scanText(string $text, TextPolicy|string|null $policy = null)
 * @method static ScanResult scanHtml(string $html, TextPolicy|string|null $policy = null)
 * @method static ScanResult scanTextOrFail(string $text, TextPolicy|string|null $policy = null)
 * @method static string sanitizeHtml(string $html)
 * @method static ScanResult scanUrl(string $url)
 * @method static bool isSafeUrl(string $url)
 * @method static ScanId queue(UploadedFile|FileReference|string $file, FilePolicy|string|null $policy = null)
 * @method static MalwareScanner scanner(string|null $name = null)
 * @method static list<ScannerHealth> health()
 * @method static ContentSecurityManager extend(string $driver, Closure $factory)
 * @method static ContentSecurityManager addFileCheck(string $check, string|null $before = null, string|null $after = null)
 * @method static ContentSecurityManager addTextCheck(string $check, string|null $before = null, string|null $after = null)
 * @method static ContentSecurityManager removeCheck(string $check)
 * @method static ContentSecurityManager beforeScan(Closure $callback)
 * @method static ContentSecurityManager afterScan(Closure $callback)
 * @method static ContentSecurityManager resolveFilePolicyUsing(Closure $resolver)
 * @method static ContentSecurityManager resolveTextPolicyUsing(Closure $resolver)
 * @method static ContentSecurityManager auth(Closure $callback)
 * @method static bool authorize(mixed $user)
 * @method static HookRegistry hooks()
 * @method static CheckRegistry checks()
 *
 * @see ContentSecurityManager
 */
final class ContentSecurity extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return ContentSecurityManager::class;
    }
}
