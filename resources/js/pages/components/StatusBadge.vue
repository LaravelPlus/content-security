<script setup lang="ts">
import { computed } from 'vue';
import type { ScanStatus } from '../types';
import Icon from './Icon.vue';
import type { IconName } from './Icon.vue';

const props = withDefaults(
    defineProps<{ status: ScanStatus; withIcon?: boolean }>(),
    { withIcon: true },
);

/**
 * Colour is never the only signal: each status carries its own icon and its
 * own word, so the table still reads correctly in greyscale and to anyone
 * who cannot distinguish red from green.
 */
const styles: Record<ScanStatus, { class: string; icon: IconName }> = {
    clean: {
        class: 'bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-400/30',
        icon: 'check',
    },
    suspicious: {
        class: 'bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/10 dark:text-amber-300 dark:ring-amber-400/30',
        icon: 'alert',
    },
    infected: {
        class: 'bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/10 dark:text-red-300 dark:ring-red-400/30',
        icon: 'bug',
    },
    quarantined: {
        class: 'bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/10 dark:text-red-300 dark:ring-red-400/30',
        icon: 'lock',
    },
    failed: {
        class: 'bg-orange-50 text-orange-700 ring-orange-600/20 dark:bg-orange-500/10 dark:text-orange-300 dark:ring-orange-400/30',
        icon: 'shield-alert',
    },
    pending: {
        class: 'bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-500/10 dark:text-slate-300 dark:ring-slate-400/25',
        icon: 'clock',
    },
    scanning: {
        class: 'bg-sky-50 text-sky-700 ring-sky-600/20 dark:bg-sky-500/10 dark:text-sky-300 dark:ring-sky-400/30',
        icon: 'scan',
    },
};

const style = computed(() => styles[props.status] ?? styles.pending);
</script>

<template>
    <span
        class="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset"
        :class="style.class"
    >
        <Icon v-if="props.withIcon" :name="style.icon" :size="12" />
        {{ props.status }}
    </span>
</template>
