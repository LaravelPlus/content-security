<script setup lang="ts">
import { computed } from 'vue';
import Icon from './Icon.vue';
import type { IconName } from './Icon.vue';

const props = withDefaults(
    defineProps<{
        label: string;
        value: string | number;
        hint?: string;
        icon?: IconName;
        tone?: 'neutral' | 'good' | 'warn' | 'bad';
        /** Renders a muted card when the figure is zero and that is good news. */
        quietWhenZero?: boolean;
    }>(),
    { tone: 'neutral', quietWhenZero: false },
);

const isQuiet = computed(
    () => props.quietWhenZero && (props.value === 0 || props.value === '0'),
);

const tones = {
    neutral: 'text-slate-900 dark:text-slate-100',
    good: 'text-emerald-600 dark:text-emerald-400',
    warn: 'text-amber-600 dark:text-amber-400',
    bad: 'text-red-600 dark:text-red-400',
};
</script>

<template>
    <div
        class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
    >
        <div class="flex items-center gap-2">
            <Icon
                v-if="props.icon"
                :name="props.icon"
                :size="14"
                class="text-slate-400 dark:text-slate-500"
            />
            <p class="text-xs text-slate-500 dark:text-slate-400">
                {{ props.label }}
            </p>
        </div>

        <p
            class="mt-2 text-2xl font-semibold tabular-nums"
            :class="
                isQuiet
                    ? 'text-slate-400 dark:text-slate-600'
                    : tones[props.tone]
            "
        >
            {{ props.value }}
        </p>

        <p
            v-if="props.hint"
            class="mt-1 text-xs text-slate-500 dark:text-slate-400"
        >
            {{ props.hint }}
        </p>
    </div>
</template>
