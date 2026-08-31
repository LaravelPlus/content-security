<script setup lang="ts">
import { computed } from 'vue';
import type { TimelinePoint } from '../types';

const props = defineProps<{ points: TimelinePoint[] }>();

const max = computed(() =>
    Math.max(1, ...props.points.map((point) => point.total)),
);

const label = (bucket: string): string => bucket.slice(-5).replace(':00', 'h');
</script>

<template>
    <div
        class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
    >
        <p
            class="text-[11px] font-semibold tracking-wider text-slate-500 uppercase dark:text-slate-400"
        >
            Scan volume
        </p>

        <div
            v-if="props.points.length === 0"
            class="mt-6 pb-4 text-center text-xs text-slate-400 dark:text-slate-600"
        >
            No activity in this window.
        </div>

        <!-- items-stretch, not items-end: the bars size themselves with
             percentage heights, and a column that only wraps its content
             gives them 0px to resolve against. -->
        <div
            v-else
            class="mt-4 flex h-28 items-stretch gap-1"
            role="img"
            aria-label="Scan volume over time"
        >
            <div
                v-for="point in props.points"
                :key="point.bucket"
                class="group relative flex flex-1 flex-col justify-end"
                :title="`${point.bucket}: ${point.total} scans, ${point.threats} with findings`"
            >
                <!-- Findings stack on top of the clean count rather than
                     sitting beside it: the eye should read total height as
                     volume and the red cap as how much of it was trouble. -->
                <div
                    v-if="point.threats > 0"
                    class="w-full rounded-t bg-red-500"
                    :style="{ height: `${(point.threats / max) * 100}%` }"
                />
                <div
                    class="w-full bg-slate-300 group-hover:bg-slate-400 dark:bg-slate-700 dark:group-hover:bg-slate-600"
                    :class="point.threats > 0 ? '' : 'rounded-t'"
                    :style="{
                        height: `${((point.total - point.threats) / max) * 100}%`,
                    }"
                />
            </div>
        </div>

        <div
            v-if="props.points.length > 1"
            class="mt-2 flex justify-between text-[10px] text-slate-400 tabular-nums dark:text-slate-600"
        >
            <span>{{ label(props.points[0].bucket) }}</span>
            <span>{{
                label(props.points[props.points.length - 1].bucket)
            }}</span>
        </div>
    </div>
</template>
