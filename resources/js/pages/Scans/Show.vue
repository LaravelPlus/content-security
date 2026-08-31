<script setup lang="ts">
import { Head, Link } from '@inertiajs/vue3';
import { computed } from 'vue';
import Icon from '../components/Icon.vue';
import SecurityTimeline from '../components/SecurityTimeline.vue';
import StatusBadge from '../components/StatusBadge.vue';
import ThreatBadge from '../components/ThreatBadge.vue';
import {
    formatBytes,
    formatDate,
    formatDuration,
    useConsole,
} from '../composables/useConsole';
import SecurityAdminLayout from '../layouts/SecurityAdminLayout.vue';
import type { Scan, ScanEvent } from '../types';

const props = defineProps<{ scan: Scan; timeline: ScanEvent[] }>();

const { route, shared } = useConsole();

const checkLabels: Record<string, string> = {
    size: 'File size',
    extension: 'Extension',
    mime: 'MIME type',
    magic_bytes: 'Magic bytes',
    archive: 'Archive inspection',
    image: 'Image validation',
    pdf: 'PDF inspection',
    malware: 'Malware scan',
    length: 'Length',
    suspicious: 'Suspicious content',
    html: 'HTML sanitization',
    urls: 'URLs',
};

const checks = computed(() => props.scan.checks ?? []);

const details = computed(() => {
    const rows: Array<{ label: string; value: string; mono?: boolean }> = [
        { label: 'Scan ID', value: props.scan.id, mono: true },
        { label: 'Type', value: props.scan.type },
        { label: 'Policy', value: props.scan.policy ?? '—' },
        { label: 'Scanner', value: props.scan.scanner ?? '—' },
        { label: 'Duration', value: formatDuration(props.scan.duration_ms) },
        { label: 'Started', value: formatDate(props.scan.created_at) },
        { label: 'Completed', value: formatDate(props.scan.completed_at) },
    ];

    if (props.scan.type === 'file') {
        rows.push(
            { label: 'Filename', value: props.scan.subject },
            {
                label: 'Extension',
                value: props.scan.extension ? `.${props.scan.extension}` : '—',
            },
            { label: 'Size', value: formatBytes(props.scan.size) },
            {
                label: 'Declared MIME',
                value: props.scan.declared_mime ?? '—',
                mono: true,
            },
            {
                label: 'Detected MIME',
                value: props.scan.detected_mime ?? '—',
                mono: true,
            },
        );
    } else {
        rows.push({
            label: 'Length',
            value: props.scan.content_length
                ? `${props.scan.content_length.toLocaleString()} characters`
                : '—',
        });
    }

    rows.push({
        label: 'SHA-256',
        value: props.scan.checksum ?? '—',
        mono: true,
    });

    if (shared.value.exposePaths && props.scan.quarantine_path) {
        rows.push({
            label: 'Quarantine path',
            value: props.scan.quarantine_path,
            mono: true,
        });
    }

    return rows;
});
</script>

<template>
    <Head :title="`Scan ${props.scan.short_id} — Content Security`" />

    <SecurityAdminLayout>
        <template #title>
            <span class="flex items-center gap-3">
                Scan {{ props.scan.short_id }}
                <StatusBadge :status="props.scan.status" />
            </span>
        </template>
        <template #description>{{ props.scan.subject }}</template>

        <Link
            :href="route('scans')"
            class="mb-4 inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
        >
            <Icon name="chevron-left" :size="13" /> All scans
        </Link>

        <div class="grid gap-5 lg:grid-cols-3">
            <div class="space-y-5 lg:col-span-2">
                <section
                    class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
                >
                    <h2 class="text-sm font-semibold">Details</h2>
                    <dl class="mt-3 grid gap-x-6 gap-y-2.5 sm:grid-cols-2">
                        <div
                            v-for="row in details"
                            :key="row.label"
                            class="min-w-0"
                        >
                            <dt
                                class="text-[11px] tracking-wide text-slate-500 uppercase dark:text-slate-400"
                            >
                                {{ row.label }}
                            </dt>
                            <dd
                                class="truncate text-sm text-slate-800 dark:text-slate-200"
                                :class="row.mono ? 'font-mono text-xs' : ''"
                                :title="row.value"
                            >
                                {{ row.value }}
                            </dd>
                        </div>
                    </dl>
                </section>

                <section
                    class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
                >
                    <h2 class="text-sm font-semibold">Security checks</h2>

                    <ul
                        v-if="checks.length > 0"
                        class="mt-3 divide-y divide-slate-100 dark:divide-slate-800/70"
                    >
                        <li
                            v-for="check in checks"
                            :key="check.check"
                            class="flex items-center justify-between gap-3 py-2"
                        >
                            <span class="flex min-w-0 items-center gap-2">
                                <span
                                    class="flex h-5 w-5 shrink-0 items-center justify-center rounded-full"
                                    :class="{
                                        'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400':
                                            check.status === 'clean' &&
                                            !check.skipped,
                                        'bg-slate-100 text-slate-400 dark:bg-slate-800 dark:text-slate-500':
                                            check.skipped,
                                        'bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-400':
                                            check.status === 'suspicious',
                                        'bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-400':
                                            check.status === 'infected' ||
                                            check.status === 'failed',
                                    }"
                                >
                                    <Icon
                                        :name="
                                            check.skipped
                                                ? 'chevron-right'
                                                : check.status === 'clean'
                                                  ? 'check'
                                                  : 'x'
                                        "
                                        :size="11"
                                    />
                                </span>
                                <span class="truncate text-sm">
                                    {{
                                        checkLabels[check.check] ?? check.check
                                    }}
                                </span>
                                <span
                                    v-if="check.skipped"
                                    class="shrink-0 rounded bg-slate-100 px-1.5 py-0.5 text-[10px] tracking-wide text-slate-500 uppercase dark:bg-slate-800 dark:text-slate-400"
                                >
                                    skipped
                                </span>
                            </span>

                            <span
                                class="shrink-0 text-xs text-slate-400 tabular-nums dark:text-slate-500"
                            >
                                {{
                                    check.duration_ms > 0
                                        ? `${check.duration_ms} ms`
                                        : '—'
                                }}
                            </span>
                        </li>
                    </ul>

                    <p
                        v-else
                        class="mt-3 text-xs text-slate-500 dark:text-slate-400"
                    >
                        No per-check detail was recorded for this scan.
                    </p>
                </section>

                <section
                    v-if="props.scan.threats && props.scan.threats.length > 0"
                    class="rounded-lg border border-red-200 bg-white dark:border-red-500/30 dark:bg-slate-900"
                >
                    <h2
                        class="border-b border-red-200 px-4 py-3 text-sm font-semibold text-red-800 dark:border-red-500/30 dark:text-red-300"
                    >
                        Findings ({{ props.scan.threats.length }})
                    </h2>
                    <ul
                        class="divide-y divide-slate-100 dark:divide-slate-800/70"
                    >
                        <li
                            v-for="threat in props.scan.threats"
                            :key="threat.id ?? threat.name"
                            class="px-4 py-3"
                        >
                            <div class="flex items-start justify-between gap-3">
                                <div class="min-w-0">
                                    <p class="font-mono text-sm">
                                        {{ threat.name }}
                                    </p>
                                    <p
                                        v-if="threat.description"
                                        class="mt-1 text-xs text-slate-600 dark:text-slate-400"
                                    >
                                        {{ threat.description }}
                                    </p>
                                    <p
                                        class="mt-1 text-[11px] tracking-wide text-slate-400 uppercase dark:text-slate-500"
                                    >
                                        Detected by {{ threat.source }}
                                    </p>
                                </div>
                                <ThreatBadge :level="threat.level" />
                            </div>
                        </li>
                    </ul>
                </section>
            </div>

            <aside>
                <section
                    class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
                >
                    <h2 class="mb-4 text-sm font-semibold">Timeline</h2>
                    <SecurityTimeline :events="props.timeline" />
                </section>

                <p
                    v-if="!shared.exposePaths"
                    class="mt-3 px-1 text-[11px] leading-relaxed text-slate-400 dark:text-slate-600"
                >
                    Filesystem paths are hidden. Enable
                    <span class="font-mono">admin.expose_paths</span> to show
                    them.
                </p>
            </aside>
        </div>
    </SecurityAdminLayout>
</template>
