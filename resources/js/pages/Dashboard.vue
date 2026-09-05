<script setup lang="ts">
import { Head, Link, router } from '@inertiajs/vue3';
import { computed } from 'vue';
import ActivityChart from './components/ActivityChart.vue';
import Icon from './components/Icon.vue';
import type { IconName } from './components/Icon.vue';
import ScanTable from './components/ScanTable.vue';
import ThreatBadge from './components/ThreatBadge.vue';
import {
    formatDate,
    formatDuration,
    formatNumber,
    useConsole,
} from './composables/useConsole';
import SecurityAdminLayout from './layouts/SecurityAdminLayout.vue';
import type {
    Posture,
    Scan,
    ScannerHealth,
    Statistics,
    Threat,
    TimelinePoint,
} from './types';

const props = defineProps<{
    statistics: Statistics;
    /** Stanje, ne okno: kar caka, caka tudi cez teden dni. */
    waiting: { threats: number; quarantined: number; failed: number };
    hours: number;
    health: ScannerHealth[];
    posture: Posture;
    recentScans: Scan[];
    recentThreats: Threat[];
    timeline: TimelinePoint[];
}>();

const { route } = useConsole();

/*
 * Ta zaslon odgovarja na dve vprasanji, in to v tem vrstnem redu: ali zdaj
 * kaj gori, in kaj caka mene. Sele za tem pridejo stevilke, ki povedo, koliko
 * dela je bilo opravljenega -- te niso naloga, ampak zapis.
 */
const posture = computed(() => {
    switch (props.posture.state) {
        case 'critical':
            return {
                tone: 'border-red-200 bg-red-50 dark:border-red-500/30 dark:bg-red-500/10',
                dot: 'bg-red-500',
                title: 'text-red-900 dark:text-red-200',
                body: 'text-red-800/80 dark:text-red-300/90',
                icon: 'shield-alert' as IconName,
                iconTone: 'text-red-600 dark:text-red-400',
            };
        case 'warning':
            return {
                tone: 'border-amber-200 bg-amber-50 dark:border-amber-500/30 dark:bg-amber-500/10',
                dot: 'bg-amber-500',
                title: 'text-amber-900 dark:text-amber-200',
                body: 'text-amber-800/80 dark:text-amber-300/90',
                icon: 'alert' as IconName,
                iconTone: 'text-amber-600 dark:text-amber-400',
            };
        default:
            return {
                tone: 'border-emerald-200 bg-emerald-50 dark:border-emerald-500/30 dark:bg-emerald-500/10',
                dot: 'bg-emerald-500',
                title: 'text-emerald-900 dark:text-emerald-200',
                body: 'text-emerald-800/80 dark:text-emerald-300/90',
                icon: 'shield' as IconName,
                iconTone: 'text-emerald-600 dark:text-emerald-400',
            };
    }
});

const offlineScanner = computed(() =>
    props.health.find((engine) => engine.active && !engine.online),
);

/*
 * Kaj caka cloveka. Nic ni tudi odgovor -- in dober -- zato se vrstica pokaze
 * tudi takrat, samo tiho.
 */
const queue = computed(() => [
    {
        key: 'threats',
        label: 'Findings to review',
        count: props.waiting.threats,
        href: route('threats'),
        empty: 'Nothing has been flagged.',
        icon: 'bug' as IconName,
    },
    {
        key: 'quarantine',
        label: 'Files in quarantine',
        count: props.waiting.quarantined,
        href: route('quarantine'),
        empty: 'Quarantine is empty.',
        icon: 'lock' as IconName,
    },
    {
        key: 'failed',
        label: 'Scans that could not finish',
        count: props.waiting.failed,
        href: `${route('scans')}?status=failed`,
        empty: 'Every scan completed.',
        icon: 'alert' as IconName,
    },
]);

const waiting = computed(() => queue.value.some((item) => item.count > 0));

/** Kaj je bilo pregledano: zapis o delu, ne naloga. */
const throughput = computed(() => [
    { label: 'Scanned', value: formatNumber(props.statistics.window_total) },
    { label: 'Clean', value: formatNumber(props.statistics.clean) },
    { label: 'Suspicious', value: formatNumber(props.statistics.suspicious) },
    { label: 'Malware', value: formatNumber(props.statistics.infected) },
    {
        label: 'Average scan',
        value: formatDuration(props.statistics.avg_duration_ms),
    },
    { label: 'On record', value: formatNumber(props.statistics.total) },
]);

const windows = [
    { label: '24 hours', hours: 24 },
    { label: '7 days', hours: 168 },
    { label: '30 days', hours: 720 },
];

const busiest = computed(() =>
    props.timeline.reduce((peak, point) => Math.max(peak, point.total), 0),
);

const setWindow = (hours: number): void => {
    router.get(
        route(''),
        { hours },
        { preserveScroll: true, preserveState: true },
    );
};
</script>

<template>
    <Head title="Content Security" />

    <SecurityAdminLayout>
        <template #title>Overview</template>
        <template #description>
            Uploads and untrusted content, as the scanner saw them.
        </template>

        <template #actions>
            <div
                class="flex rounded-lg border border-slate-200 bg-white p-0.5 dark:border-slate-800 dark:bg-slate-900"
            >
                <button
                    v-for="option in windows"
                    :key="option.hours"
                    type="button"
                    class="rounded-md px-2.5 py-1 text-xs font-medium transition focus-visible:ring-2 focus-visible:ring-slate-400 focus-visible:outline-none"
                    :class="
                        props.hours === option.hours
                            ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                            : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100'
                    "
                    @click="setWindow(option.hours)"
                >
                    {{ option.label }}
                </button>
            </div>
        </template>

        <!-- 1. Ali zdaj kaj gori. -->
        <section
            class="flex flex-wrap items-start gap-4 rounded-xl border p-5"
            :class="posture.tone"
        >
            <span class="mt-0.5 shrink-0" :class="posture.iconTone">
                <Icon :name="posture.icon" :size="22" />
            </span>

            <div class="min-w-0 flex-1">
                <h2 class="text-base font-semibold" :class="posture.title">
                    {{ props.posture.headline }}
                </h2>
                <p class="mt-0.5 text-sm" :class="posture.body">
                    {{ props.posture.detail }}
                </p>
            </div>

            <Link
                v-if="offlineScanner"
                :href="route('health')"
                class="shrink-0 rounded-lg bg-slate-900 px-3 py-2 text-xs font-semibold text-white transition hover:bg-slate-700 focus-visible:ring-2 focus-visible:ring-slate-400 focus-visible:outline-none dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-white"
            >
                Open scanner health
            </Link>
        </section>

        <!-- 2. Kaj caka mene. -->
        <section class="mt-5 grid gap-3 sm:grid-cols-3">
            <component
                :is="item.count > 0 ? Link : 'div'"
                v-for="item in queue"
                :key="item.key"
                :href="item.count > 0 ? item.href : undefined"
                class="rounded-xl border p-4 transition"
                :class="
                    item.count > 0
                        ? 'border-slate-300 bg-white hover:border-slate-400 hover:shadow-sm dark:border-slate-700 dark:bg-slate-900'
                        : 'border-dashed border-slate-200 bg-transparent dark:border-slate-800'
                "
            >
                <span
                    class="flex items-center gap-2 text-sm"
                    :class="
                        item.count > 0
                            ? 'text-slate-600 dark:text-slate-300'
                            : 'text-slate-400 dark:text-slate-500'
                    "
                >
                    <Icon :name="item.icon" :size="15" />
                    {{ item.label }}
                </span>

                <p
                    v-if="item.count > 0"
                    class="mt-2 text-3xl font-semibold text-slate-900 tabular-nums dark:text-slate-100"
                >
                    {{ formatNumber(item.count) }}
                </p>
                <p
                    v-else
                    class="mt-2 text-sm text-slate-400 dark:text-slate-500"
                >
                    {{ item.empty }}
                </p>
            </component>
        </section>

        <p
            v-if="!waiting"
            class="mt-3 text-xs text-slate-500 dark:text-slate-400"
        >
            Nothing is waiting for you.
        </p>

        <!-- 3. Koliko dela je bilo opravljenega. -->
        <section
            class="mt-6 overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
        >
            <dl
                class="grid divide-y divide-slate-100 sm:grid-cols-3 sm:divide-x sm:divide-y-0 lg:grid-cols-6 dark:divide-slate-800"
            >
                <div
                    v-for="stat in throughput"
                    :key="stat.label"
                    class="px-4 py-3"
                >
                    <dt class="text-xs text-slate-500 dark:text-slate-400">
                        {{ stat.label }}
                    </dt>
                    <dd class="mt-1 text-xl font-semibold tabular-nums">
                        {{ stat.value }}
                    </dd>
                </div>
            </dl>
        </section>

        <!-- 4. Kdaj se je delalo. -->
        <section
            class="mt-6 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
        >
            <div class="flex items-baseline justify-between gap-3">
                <h2 class="text-sm font-semibold">Scan volume</h2>
                <p
                    v-if="busiest > 0"
                    class="text-xs text-slate-500 dark:text-slate-400"
                >
                    busiest bucket: {{ formatNumber(busiest) }}
                </p>
            </div>

            <ActivityChart
                v-if="busiest > 0"
                :points="props.timeline"
                class="mt-3"
            />
            <p
                v-else
                class="mt-6 mb-4 text-center text-sm text-slate-400 dark:text-slate-500"
            >
                Nothing was scanned in this window.
            </p>
        </section>

        <!-- 5. Kaj se je zgodilo nazadnje. -->
        <div class="mt-6 grid gap-5 lg:grid-cols-3">
            <section
                class="overflow-hidden rounded-xl border border-slate-200 bg-white lg:col-span-2 dark:border-slate-800 dark:bg-slate-900"
            >
                <div
                    class="flex items-center justify-between border-b border-slate-100 px-4 py-3 dark:border-slate-800"
                >
                    <h2 class="text-sm font-semibold">Recent scans</h2>
                    <Link
                        :href="route('scans')"
                        class="inline-flex items-center gap-1 text-xs font-medium text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
                    >
                        All scans <Icon name="chevron-right" :size="12" />
                    </Link>
                </div>

                <ScanTable
                    v-if="props.recentScans.length > 0"
                    :scans="props.recentScans"
                />
                <p
                    v-else
                    class="px-4 py-10 text-center text-sm text-slate-400 dark:text-slate-500"
                >
                    No scan has run yet.
                </p>
            </section>

            <section
                class="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
            >
                <div
                    class="flex items-center justify-between border-b border-slate-100 px-4 py-3 dark:border-slate-800"
                >
                    <h2 class="text-sm font-semibold">Latest findings</h2>
                    <Link
                        :href="route('threats')"
                        class="inline-flex items-center gap-1 text-xs font-medium text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
                    >
                        All findings <Icon name="chevron-right" :size="12" />
                    </Link>
                </div>

                <ul
                    v-if="props.recentThreats.length > 0"
                    class="divide-y divide-slate-100 dark:divide-slate-800"
                >
                    <li
                        v-for="threat in props.recentThreats"
                        :key="`${threat.name}-${threat.created_at}`"
                        class="flex items-start justify-between gap-3 px-4 py-3"
                    >
                        <div class="min-w-0">
                            <p
                                class="truncate font-mono text-xs text-slate-900 dark:text-slate-100"
                            >
                                {{ threat.name }}
                            </p>
                            <p
                                class="mt-0.5 text-xs text-slate-500 dark:text-slate-400"
                            >
                                {{ threat.source }} ·
                                {{ formatDate(threat.created_at ?? null) }}
                            </p>
                        </div>
                        <ThreatBadge :level="threat.level" />
                    </li>
                </ul>
                <p
                    v-else
                    class="px-4 py-10 text-center text-sm text-slate-400 dark:text-slate-500"
                >
                    Nothing has been flagged.
                </p>
            </section>
        </div>
    </SecurityAdminLayout>
</template>
