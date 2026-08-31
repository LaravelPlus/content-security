<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use LaravelPlus\ContentSecurity\Http\Controllers\DashboardController;
use LaravelPlus\ContentSecurity\Http\Controllers\HealthController;
use LaravelPlus\ContentSecurity\Http\Controllers\PolicyController;
use LaravelPlus\ContentSecurity\Http\Controllers\QuarantineController;
use LaravelPlus\ContentSecurity\Http\Controllers\ScanController;
use LaravelPlus\ContentSecurity\Http\Controllers\ThreatController;
use LaravelPlus\ContentSecurity\Http\Middleware\Authorize;

/**
 * The console. The host's own middleware runs first (session, auth), then
 * Authorize asks the application whether this user may see security data —
 * the package never assumes an authorization model of its own.
 */
Route::middleware([...(array) config('content-security.admin.middleware', ['web', 'auth']), Authorize::class])
    ->prefix((string) config('content-security.admin.prefix', 'admin/content-security'))
    ->name((string) config('content-security.admin.route_name', 'admin.content-security.'))
    ->group(function (): void {
        Route::get('/', DashboardController::class)->name('dashboard');

        Route::get('/scans', [ScanController::class, 'index'])->name('scans.index');
        Route::get('/scans/{scan}', [ScanController::class, 'show'])->name('scans.show');

        Route::get('/threats', ThreatController::class)->name('threats.index');

        Route::get('/quarantine', [QuarantineController::class, 'index'])->name('quarantine.index');
        Route::post('/quarantine/{scan}/rescan', [QuarantineController::class, 'rescan'])->name('quarantine.rescan');
        Route::post('/quarantine/{scan}/release', [QuarantineController::class, 'release'])->name('quarantine.release');
        Route::delete('/quarantine/{scan}', [QuarantineController::class, 'destroy'])->name('quarantine.destroy');

        Route::get('/policies', [PolicyController::class, 'index'])->name('policies.index');
        Route::put('/policies/{policy}', [PolicyController::class, 'update'])->name('policies.update');
        Route::post('/policies/{policy}/reset', [PolicyController::class, 'reset'])->name('policies.reset');

        Route::get('/health', [HealthController::class, 'index'])->name('health.index');
        Route::post('/health/test', [HealthController::class, 'test'])->name('health.test');
    });
