<script setup lang="ts">
import { Link } from '@inertiajs/vue3';
import StatusBadge from './StatusBadge.vue';
import Icon from './Icon.vue';
import EmptyState from './EmptyState.vue';
import { formatBytes, formatDate, formatDuration, useConsole } from '../composables/useConsole';
import type { Scan } from '../types';

const props = withDefaults(
    defineProps<{ scans: Scan[]; compact?: boolean }>(),
    { compact: false },
);

const { route } = useConsole();
</script>

<template>
    <EmptyState
        v-if="props.scans.length === 0"
        title="No scans yet"
        description="Scans appear here as soon as content passes through a validation rule or the scanning API."
    />

    <!-- Wide table, narrow viewports: the table scrolls inside its own box
         rather than making the whole page scroll sideways. -->
    <div
        v-else
        class="overflow-x-auto rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
    >
        <table class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">
            <thead>
                <tr class="text-left text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    <th scope="col" class="px-4 py-2.5 font-semibold">Scan</th>
                    <th scope="col" class="px-4 py-2.5 font-semibold">Date</th>
                    <th scope="col" class="px-4 py-2.5 font-semibold">Type</th>
                    <th scope="col" class="px-4 py-2.5 font-semibold">Subject</th>
                    <th v-if="!props.compact" scope="col" class="px-4 py-2.5 font-semibold">MIME</th>
                    <th v-if="!props.compact" scope="col" class="px-4 py-2.5 font-semibold">Size</th>
                    <th scope="col" class="px-4 py-2.5 font-semibold">Status</th>
                    <th scope="col" class="px-4 py-2.5 text-right font-semibold">Threats</th>
                    <th v-if="!props.compact" scope="col" class="px-4 py-2.5 font-semibold">Scanner</th>
                    <th scope="col" class="px-4 py-2.5 text-right font-semibold">Duration</th>
                    <th scope="col" class="px-4 py-2.5"><span class="sr-only">Open</span></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-100 dark:divide-slate-800/70">
                <tr
                    v-for="scan in props.scans"
                    :key="scan.id"
                    class="hover:bg-slate-50 dark:hover:bg-slate-800/40"
                >
                    <td class="px-4 py-2.5 font-mono text-xs text-slate-500 dark:text-slate-400">
                        {{ scan.short_id }}
                    </td>
                    <td class="whitespace-nowrap px-4 py-2.5 text-slate-600 dark:text-slate-400">
                        {{ formatDate(scan.created_at) }}
                    </td>
                    <td class="px-4 py-2.5 uppercase text-[11px] tracking-wide text-slate-500 dark:text-slate-400">
                        {{ scan.type }}
                    </td>
                    <td class="max-w-[18rem] truncate px-4 py-2.5" :title="scan.subject">
                        {{ scan.subject }}
                    </td>
                    <td v-if="!props.compact" class="px-4 py-2.5 font-mono text-xs text-slate-500 dark:text-slate-400">
                        {{ scan.detected_mime ?? '—' }}
                    </td>
                    <td v-if="!props.compact" class="whitespace-nowrap px-4 py-2.5 tabular-nums text-slate-600 dark:text-slate-400">
                        {{ formatBytes(scan.size) }}
                    </td>
                    <td class="px-4 py-2.5">
                        <StatusBadge :status="scan.status" />
                    </td>
                    <td
                        class="px-4 py-2.5 text-right tabular-nums"
                        :class="scan.threat_count > 0 ? 'font-semibold text-red-600 dark:text-red-400' : 'text-slate-400 dark:text-slate-600'"
                    >
                        {{ scan.threat_count }}
                    </td>
                    <td v-if="!props.compact" class="px-4 py-2.5 text-slate-600 dark:text-slate-400">
                        {{ scan.scanner ?? '—' }}
                    </td>
                    <td class="whitespace-nowrap px-4 py-2.5 text-right tabular-nums text-slate-600 dark:text-slate-400">
                        {{ formatDuration(scan.duration_ms) }}
                    </td>
                    <td class="px-4 py-2.5 text-right">
                        <Link
                            :href="route(`scans/${scan.id}`)"
                            class="inline-flex items-center text-slate-400 hover:text-slate-900 dark:hover:text-slate-100"
                            :aria-label="`Open scan ${scan.short_id}`"
                        >
                            <Icon name="chevron-right" :size="16" />
                        </Link>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
</template>
