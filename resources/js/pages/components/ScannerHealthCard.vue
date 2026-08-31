<script setup lang="ts">
import { computed } from 'vue';
import Icon from './Icon.vue';
import { formatDate } from '../composables/useConsole';
import type { ScannerHealth } from '../types';

const props = defineProps<{ health: ScannerHealth }>();

/**
 * Only the ACTIVE engine can be a problem. Every configured driver is listed,
 * so an idle `null` sitting in config used to render an alarming card next to
 * a perfectly healthy ClamAV — which is how an operator learns to distrust
 * this page.
 */
const tone = computed(() => {
    if (props.health.is_problem) {
        return {
            dot: 'bg-red-500',
            text: 'text-red-700 dark:text-red-400',
            // With fail-closed on, this is the state in which every upload is
            // being rejected.
            ring: 'border-red-300 dark:border-red-500/40',
        };
    }

    if (props.health.online) {
        return {
            dot: 'bg-emerald-500',
            text: 'text-emerald-700 dark:text-emerald-400',
            ring: 'border-slate-200 dark:border-slate-800',
        };
    }

    return {
        dot: 'bg-slate-300 dark:bg-slate-600',
        text: 'text-slate-400 dark:text-slate-500',
        ring: 'border-slate-200 dark:border-slate-800',
    };
});
</script>

<template>
    <div
        class="rounded-lg border bg-white p-4 dark:bg-slate-900"
        :class="tone.ring"
    >
        <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
                <p class="flex items-center gap-2 font-medium capitalize">
                    {{ props.health.scanner }}
                    <span
                        v-if="props.health.active"
                        class="rounded bg-slate-900 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-white dark:bg-slate-100 dark:text-slate-900"
                    >
                        active
                    </span>
                </p>
                <p
                    v-if="props.health.connection"
                    class="mt-0.5 truncate font-mono text-[11px] text-slate-500 dark:text-slate-400"
                    :title="props.health.connection"
                >
                    {{ props.health.connection }}
                </p>
            </div>

            <span class="flex items-center gap-1.5 text-xs font-semibold uppercase" :class="tone.text">
                <span class="h-2 w-2 rounded-full" :class="tone.dot" />
                {{ props.health.status }}
            </span>
        </div>

        <dl class="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
            <div v-if="props.health.version">
                <dt class="text-slate-500 dark:text-slate-400">Version</dt>
                <dd class="font-mono text-slate-700 dark:text-slate-300">
                    {{ props.health.version }}
                </dd>
            </div>
            <div v-if="props.health.signature_version">
                <dt class="text-slate-500 dark:text-slate-400">Signatures</dt>
                <dd class="font-mono text-slate-700 dark:text-slate-300">
                    {{ props.health.signature_version }}
                </dd>
            </div>
            <div v-if="props.health.signatures_updated_at">
                <dt class="text-slate-500 dark:text-slate-400">Updated</dt>
                <dd class="text-slate-700 dark:text-slate-300">
                    {{ formatDate(props.health.signatures_updated_at) }}
                </dd>
            </div>
            <div v-if="props.health.ping_ms !== null">
                <dt class="text-slate-500 dark:text-slate-400">Ping</dt>
                <dd class="tabular-nums text-slate-700 dark:text-slate-300">
                    {{ Math.round(props.health.ping_ms) }} ms
                </dd>
            </div>
        </dl>

        <p
            v-if="props.health.error && props.health.is_problem"
            class="mt-3 flex items-start gap-1.5 rounded border border-red-200 bg-red-50 px-2 py-1.5 text-xs text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300"
        >
            <Icon name="alert" :size="13" class="mt-0.5 shrink-0" />
            {{ props.health.error }}
        </p>

        <p
            v-else-if="props.health.error"
            class="mt-3 text-xs text-slate-400 dark:text-slate-500"
        >
            {{ props.health.error }}
        </p>

        <slot />
    </div>
</template>
