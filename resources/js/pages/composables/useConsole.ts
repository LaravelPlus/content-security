import { usePage } from '@inertiajs/vue3';
import { computed } from 'vue';
import type { ConsoleShared } from '../types';

/**
 * Reads the console's shared props. The base path is configurable
 * (`content-security.admin.prefix`), so nothing in the UI may hardcode
 * /admin/content-security — every link is built from this.
 */
export function useConsole() {
    const page = usePage();

    const shared = computed<ConsoleShared>(
        () =>
            (page.props.contentSecurity as ConsoleShared | undefined) ?? {
                basePath: '/admin/content-security',
                brand: 'Content Security',
                backUrl: '/',
                backLabel: 'Back',
                exposePaths: false,
            },
    );

    const base = computed(() => shared.value.basePath.replace(/\/$/, ''));

    const route = (path = ''): string =>
        path === '' ? base.value : `${base.value}/${path.replace(/^\//, '')}`;

    return { shared, base, route };
}

export function formatBytes(bytes: number | null | undefined): string {
    if (bytes === null || bytes === undefined) {
        return '—';
    }

    if (bytes === 0) {
        return '0 B';
    }

    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const exponent = Math.min(
        Math.floor(Math.log(bytes) / Math.log(1024)),
        units.length - 1,
    );
    const value = bytes / 1024 ** exponent;

    return `${exponent === 0 ? value : value.toFixed(1)} ${units[exponent]}`;
}

export function formatDuration(ms: number | null | undefined): string {
    if (ms === null || ms === undefined) {
        return '—';
    }

    if (ms < 1000) {
        return `${Math.round(ms)} ms`;
    }

    return `${(ms / 1000).toFixed(2)} s`;
}

export function formatDate(value: string | null | undefined): string {
    if (!value) {
        return '—';
    }

    return new Date(value).toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
    });
}

export function formatNumber(value: number | null | undefined): string {
    return (value ?? 0).toLocaleString();
}
