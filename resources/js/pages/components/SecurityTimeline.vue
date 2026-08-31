<script setup lang="ts">
import { formatDate } from '../composables/useConsole';
import type { ScanEvent } from '../types';
import Icon from './Icon.vue';

defineProps<{ events: ScanEvent[] }>();
</script>

<template>
    <ol
        class="relative space-y-4 border-l border-slate-200 pl-5 dark:border-slate-800"
    >
        <li v-for="(event, index) in events" :key="index" class="relative">
            <span
                class="absolute -left-[26px] flex h-4 w-4 items-center justify-center rounded-full ring-4 ring-white dark:ring-slate-950"
                :class="{
                    'bg-emerald-500 text-white': event.state === 'done',
                    'bg-red-500 text-white': event.state === 'alert',
                    'bg-slate-300 text-slate-600 dark:bg-slate-700 dark:text-slate-300':
                        event.state === 'pending',
                }"
            >
                <Icon
                    :name="
                        event.state === 'alert'
                            ? 'alert'
                            : event.state === 'done'
                              ? 'check'
                              : 'clock'
                    "
                    :size="9"
                />
            </span>

            <p class="text-sm font-medium text-slate-800 dark:text-slate-200">
                {{ event.label }}
            </p>
            <p class="text-xs text-slate-500 dark:text-slate-400">
                {{ formatDate(event.at) }}
            </p>
        </li>
    </ol>
</template>
