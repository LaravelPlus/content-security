<script setup lang="ts">
import { Head, Link, router } from '@inertiajs/vue3';
import { computed } from 'vue';
import ActivityChart from './components/ActivityChart.vue';
import Icon from './components/Icon.vue';
import MetricCard from './components/MetricCard.vue';
import ScannerHealthCard from './components/ScannerHealthCard.vue';
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
    hours: number;
    health: ScannerHealth[];
    posture: Posture;
    recentScans: Scan[];
    recentThreats: Threat[];
    timeline: TimelinePoint[];
}>();

const { route } = useConsole();

const postureStyle = computed(() => {
    switch (props.posture.state) {
        case 'critical':
            return {
                wrap: 'border-red-300 bg-red-50 dark:border-red-500/40 dark:bg-red-500/10',
                icon: 'text-red-600 dark:text-red-400',
                title: 'text-red-900 dark:text-red-200',
                body: 'text-red-700 dark:text-red-300',
                name: 'shield-alert' as const,
            };
        case 'warning':
            return {
                wrap: 'border-amber-300 bg-amber-50 dark:border-amber-500/40 dark:bg-amber-500/10',
                icon: 'text-amber-600 dark:text-amber-400',
                title: 'text-amber-900 dark:text-amber-200',
                body: 'text-amber-700 dark:text-amber-300',
                name: 'alert' as const,
            };
        default:
            return {
                wrap: 'border-emerald-300 bg-emerald-50 dark:border-emerald-500/40 dark:bg-emerald-500/10',
                icon: 'text-emerald-600 dark:text-emerald-400',
                title: 'text-emerald-900 dark:text-emerald-200',
                body: 'text-emerald-700 dark:text-emerald-300',
                name: 'shield' as const,
            };
    }
});

const windows = [
    { label: '24 hours', hours: 24 },
    { label: '7 days', hours: 168 },
    { label: '30 days', hours: 720 },
];

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
            Uploads and untrusted content checked over the last
            {{
                props.hours >= 24
                    ? `${Math.round(props.hours / 24)} day(s)`
                    : `${props.hours} hour(s)`
            }}.
        </template>

        <div class="flex flex-wrap items-center justify-between gap-3">
            <div
                class="flex flex-1 items-start gap-3 rounded-lg border px-4 py-3"
                :class="postureStyle.wrap"
                role="status"
            >
                <Icon
                    :name="postureStyle.name"
                    :size="20"
                    :class="['mt-0.5 shrink-0', postureStyle.icon]"
                />
                <div>
                    <p
                        class="text-sm font-semibold"
                        :class="postureStyle.title"
                    >
                        {{ props.posture.headline }}
                    </p>
                    <p class="text-xs" :class="postureStyle.body">
                        {{ props.posture.detail }}
                    </p>
                </div>
            </div>

            <div
                class="flex rounded-md border border-slate-200 bg-white p-0.5 dark:border-slate-800 dark:bg-slate-900"
            >
                <button
                    v-for="option in windows"
                    :key="option.hours"
                    type="button"
                    class="rounded px-2.5 py-1 text-xs font-medium transition"
                    :class="
                        props.hours === option.hours
                            ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                            : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
                    "
                    @click="setWindow(option.hours)"
                >
                    {{ option.label }}
                </button>
            </div>
        </div>

        <div
            class="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6"
        >
            <MetricCard
                label="Scans"
                :value="formatNumber(props.statistics.window_total)"
                icon="scan"
            />
            <MetricCard
                label="Clean"
                :value="formatNumber(props.statistics.clean)"
                tone="good"
                icon="check"
            />
            <MetricCard
                label="Suspicious"
                :value="formatNumber(props.statistics.suspicious)"
                tone="warn"
                quiet-when-zero
                icon="alert"
            />
            <MetricCard
                label="Malware"
                :value="formatNumber(props.statistics.infected)"
                tone="bad"
                quiet-when-zero
                icon="bug"
            />
            <MetricCard
                label="Quarantined"
                :value="formatNumber(props.statistics.quarantined)"
                tone="bad"
                quiet-when-zero
                icon="lock"
            />
            <MetricCard
                label="Failures"
                :value="formatNumber(props.statistics.failed)"
                tone="warn"
                quiet-when-zero
                icon="shield-alert"
                hint="Scans that could not complete"
            />
        </div>

        <div class="mt-5 grid gap-5 lg:grid-cols-3">
            <div class="lg:col-span-2">
                <ActivityChart :points="props.timeline" />
            </div>

            <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
                <MetricCard
                    label="Average scan time"
                    :value="formatDuration(props.statistics.avg_duration_ms)"
                    icon="clock"
                />
                <MetricCard
                    label="Total scans on record"
                    :value="formatNumber(props.statistics.total)"
                    icon="activity"
                />
            </div>
        </div>

        <section class="mt-8">
            <div class="mb-3 flex items-center justify-between">
                <h2 class="text-sm font-semibold">Scanner health</h2>
                <Link
                    :href="route('health')"
                    class="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
                >
                    Details <Icon name="chevron-right" :size="13" />
                </Link>
            </div>

            <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                <ScannerHealthCard
                    v-for="scanner in props.health"
                    :key="scanner.scanner"
                    :health="scanner"
                />
            </div>
        </section>

        <div class="mt-8 grid gap-6 lg:grid-cols-3">
            <section class="lg:col-span-2">
                <div class="mb-3 flex items-center justify-between">
                    <h2 class="text-sm font-semibold">Recent scans</h2>
                    <Link
                        :href="route('scans')"
                        class="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
                    >
                        All scans <Icon name="chevron-right" :size="13" />
                    </Link>
                </div>
                <ScanTable :scans="props.recentScans" compact />
            </section>

            <section>
                <div class="mb-3 flex items-center justify-between">
                    <h2 class="text-sm font-semibold">Latest findings</h2>
                    <Link
                        :href="route('threats')"
                        class="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
                    >
                        All threats <Icon name="chevron-right" :size="13" />
                    </Link>
                </div>

                <div
                    v-if="props.recentThreats.length > 0"
                    class="divide-y divide-slate-100 rounded-lg border border-slate-200 bg-white dark:divide-slate-800/70 dark:border-slate-800 dark:bg-slate-900"
                >
                    <div
                        v-for="(threat, index) in props.recentThreats"
                        :key="index"
                        class="flex items-start justify-between gap-3 px-4 py-2.5"
                    >
                        <div class="min-w-0">
                            <p
                                class="truncate font-mono text-xs"
                                :title="threat.name"
                            >
                                {{ threat.name }}
                            </p>
                            <p
                                class="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400"
                            >
                                {{ threat.source }} ·
                                {{ formatDate(threat.created_at) }}
                            </p>
                        </div>
                        <ThreatBadge :level="threat.level" />
                    </div>
                </div>

                <div
                    v-else
                    class="rounded-lg border border-dashed border-slate-300 px-4 py-10 text-center text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400"
                >
                    Nothing detected in this period.
                </div>
            </section>
        </div>
    </SecurityAdminLayout>
</template>
