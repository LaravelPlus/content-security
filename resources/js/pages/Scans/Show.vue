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
import type { CheckOutcome, Scan, ScanEvent } from '../types';
import type { IconName } from '../components/Icon.vue';
import { checkExplanations, explainThreat } from '../explanations';

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

/*
 * Zakaj je bilo nekaj oznaceno.
 *
 * Zaslon je doslej povedal, katero preverjanje je padlo, ne pa cesa je nasel
 * -- clovek je nato ugibal, ali gre za nevarno datoteko ali za naso lastno
 * konvencijo poimenovanja. Razlaga se sestavi iz tega, kar je preverjanje
 * zabelezilo: napaka, ce je pregled spodletel, sicer pa najdba in podatki, ki
 * jo utemeljujejo.
 */

function threatsFor(check: string) {
    return (props.scan.threats ?? []).filter(
        (threat) => threat.source === check,
    );
}

/** Podatki preverjanja kot pari: kar je preverjanje izmerilo, v enakem jeziku. */
function evidenceFor(
    check: CheckOutcome,
): Array<{ label: string; value: string }> {
    return Object.entries(check.metadata ?? {})
        .filter(
            ([, value]) => value !== null && value !== '' && value !== false,
        )
        .map(([key, value]) => ({
            label: key.replace(/_/g, ' '),
            value: Array.isArray(value) ? value.join(', ') : String(value),
        }));
}

const statusExplanation = computed<string | null>(() => {
    switch (props.scan.status) {
        case 'suspicious':
            return 'Something about this file breaks the policy, but no malware signature matched. The checks below say what.';
        case 'failed':
            return 'A check could not complete, so the file is unproven rather than clean. The checks below carry the error.';
        case 'infected':
            return 'A malware signature matched. The findings below name it.';
        case 'quarantined':
            return 'A copy was taken into quarantine; the original was left where it was.';
        default:
            return null;
    }
});

/*
 * Kaj je bilo pregledano. Slika se pokaze, ker je "clean" ob imenu datoteke
 * podatek brez obraza -- clovek na tem zaslonu hoce videti, o cem tece beseda.
 * Vse drugo dobi ikono po svojem tipu; povezave ni, kadar datoteke ni vec
 * (nalozena je bila zacasna) ali je disk ne zna ponuditi.
 */
const preview = computed(
    () => props.scan.preview ?? { kind: 'file', url: null },
);

const previewIcon = computed<IconName>(() => {
    const known: Record<string, IconName> = {
        image: 'image',
        pdf: 'pdf',
        text: 'text',
        archive: 'archive',
    };

    return known[preview.value.kind] ?? 'file';
});

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

        <p
            v-if="statusExplanation"
            class="mb-4 rounded-md border border-slate-200 bg-white px-3 py-2 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300"
        >
            {{ statusExplanation }}
        </p>

        <div class="grid gap-5 lg:grid-cols-3">
            <div class="space-y-5 lg:col-span-2">
                <section
                    class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
                >
                    <h2 class="mb-3 text-sm font-semibold">Content</h2>

                    <div class="flex items-center gap-4">
                        <a
                            v-if="preview.kind === 'image' && preview.url"
                            :href="preview.url"
                            target="_blank"
                            rel="noopener"
                            class="shrink-0"
                            title="Open the original"
                        >
                            <img
                                :src="preview.url"
                                :alt="props.scan.subject"
                                class="max-h-40 w-56 rounded-md border border-slate-200 bg-[repeating-conic-gradient(#f1f5f9_0%_25%,white_0%_50%)] bg-[length:16px_16px] object-contain dark:border-slate-800"
                            />
                        </a>
                        <span
                            v-else
                            class="grid size-20 shrink-0 place-items-center rounded-md border border-slate-200 bg-slate-50 text-slate-400 dark:border-slate-800 dark:bg-slate-800/50"
                        >
                            <Icon :name="previewIcon" :size="28" />
                        </span>

                        <div
                            class="min-w-0 text-xs text-slate-500 dark:text-slate-400"
                        >
                            <p
                                class="truncate font-medium text-slate-900 dark:text-slate-100"
                            >
                                {{ props.scan.subject }}
                            </p>
                            <p class="mt-1">
                                {{
                                    props.scan.detected_mime ??
                                    props.scan.declared_mime ??
                                    '—'
                                }}
                                <span v-if="props.scan.size">
                                    · {{ formatBytes(props.scan.size) }}</span
                                >
                            </p>
                            <p
                                v-if="preview.kind === 'image' && !preview.url"
                                class="mt-1 text-slate-400"
                            >
                                The file itself is gone — an upload is scanned
                                before it is stored.
                            </p>
                        </div>
                    </div>
                </section>

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
                            class="py-2"
                        >
                            <div
                                class="flex items-center justify-between gap-3"
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
                                            checkLabels[check.check] ??
                                            check.check
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
                            </div>

                            <!-- Zakaj: napaka, najdba in podatki, ki jo utemeljujejo. -->
                            <div
                                v-if="
                                    !check.skipped && check.status !== 'clean'
                                "
                                class="mt-2 ml-7 rounded-md border border-slate-200 bg-slate-50 p-3 text-xs dark:border-slate-800 dark:bg-slate-800/40"
                            >
                                <p class="text-slate-600 dark:text-slate-300">
                                    {{
                                        checkExplanations[check.check] ??
                                        'The policy refused this check.'
                                    }}
                                </p>

                                <p
                                    v-if="check.error"
                                    class="mt-2 font-mono text-red-700 dark:text-red-400"
                                >
                                    {{ check.error }}
                                </p>

                                <div
                                    v-for="threat in threatsFor(check.check)"
                                    :key="threat.name"
                                    class="mt-2"
                                >
                                    <p
                                        class="font-medium text-slate-900 dark:text-slate-100"
                                    >
                                        {{ threat.name }}
                                        <span class="text-slate-400"
                                            >· {{ threat.level }}</span
                                        >
                                    </p>
                                    <p
                                        v-if="threat.description"
                                        class="text-slate-600 dark:text-slate-300"
                                    >
                                        {{ threat.description }}
                                    </p>
                                </div>

                                <dl
                                    v-if="evidenceFor(check).length > 0"
                                    class="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1"
                                >
                                    <template
                                        v-for="row in evidenceFor(check)"
                                        :key="row.label"
                                    >
                                        <dt
                                            class="text-slate-400 capitalize dark:text-slate-500"
                                        >
                                            {{ row.label }}
                                        </dt>
                                        <dd
                                            class="font-mono break-all text-slate-700 dark:text-slate-300"
                                        >
                                            {{ row.value }}
                                        </dd>
                                    </template>
                                </dl>
                            </div>
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
