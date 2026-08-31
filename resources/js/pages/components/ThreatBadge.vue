<script setup lang="ts">
import { computed } from 'vue';
import type { ThreatLevel } from '../types';

const props = defineProps<{ level: ThreatLevel }>();

const classes: Record<ThreatLevel, string> = {
    critical: 'bg-red-600 text-white dark:bg-red-500 dark:text-white',
    high: 'bg-red-50 text-red-700 ring-1 ring-inset ring-red-600/25 dark:bg-red-500/10 dark:text-red-300 dark:ring-red-400/30',
    medium: 'bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-600/25 dark:bg-amber-500/10 dark:text-amber-300 dark:ring-amber-400/30',
    low: 'bg-yellow-50 text-yellow-800 ring-1 ring-inset ring-yellow-600/20 dark:bg-yellow-500/10 dark:text-yellow-200 dark:ring-yellow-400/25',
    info: 'bg-slate-100 text-slate-600 ring-1 ring-inset ring-slate-500/20 dark:bg-slate-500/10 dark:text-slate-300 dark:ring-slate-400/25',
};

const style = computed(() => classes[props.level] ?? classes.info);
</script>

<template>
    <span
        class="inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-semibold tracking-wide uppercase"
        :class="style"
    >
        {{ props.level }}
    </span>
</template>
