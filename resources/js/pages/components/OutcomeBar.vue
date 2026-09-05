<script setup lang="ts">
import { computed } from 'vue';

/**
 * Kako se pregledi koncajo, kot deli celote.
 *
 * Stanja nosijo rezervirane barve (dobro / opozorilo / resno / nevtralno) in
 * gredo vedno z oznako in stevilko -- barva sama ni podatek za tistega, ki je
 * ne loci. Rezine so locene z rezo v barvi podlage, da se dve sosednji ne
 * zlijeta v eno.
 */
const props = defineProps<{
    outcomes: Array<{ key: string; label: string; value: number }>;
}>();

const tone: Record<string, { fill: string; dot: string }> = {
    clean: { fill: 'bg-emerald-500', dot: 'bg-emerald-500' },
    suspicious: { fill: 'bg-amber-500', dot: 'bg-amber-500' },
    infected: { fill: 'bg-red-500', dot: 'bg-red-500' },
    failed: {
        fill: 'bg-slate-400 dark:bg-slate-500',
        dot: 'bg-slate-400 dark:bg-slate-500',
    },
};

const total = computed(() =>
    props.outcomes.reduce((sum, outcome) => sum + outcome.value, 0),
);

const share = (value: number): number =>
    total.value === 0 ? 0 : Math.round((value / total.value) * 100);
</script>

<template>
    <div v-if="total > 0">
        <div class="flex h-3 gap-0.5 overflow-hidden rounded-full">
            <div
                v-for="outcome in props.outcomes"
                :key="outcome.key"
                class="first:rounded-l-full last:rounded-r-full"
                :class="tone[outcome.key]?.fill ?? 'bg-slate-400'"
                :style="{ width: `${(outcome.value / total) * 100}%` }"
                :title="`${outcome.label}: ${outcome.value} (${share(outcome.value)}%)`"
            />
        </div>

        <ul class="mt-3 flex flex-wrap gap-x-5 gap-y-1.5">
            <li
                v-for="outcome in props.outcomes"
                :key="outcome.key"
                class="flex items-center gap-1.5 text-xs"
            >
                <span
                    class="size-2 rounded-sm"
                    :class="tone[outcome.key]?.dot ?? 'bg-slate-400'"
                />
                <span class="text-slate-600 dark:text-slate-300">{{
                    outcome.label
                }}</span>
                <span
                    class="font-semibold text-slate-900 tabular-nums dark:text-slate-100"
                >
                    {{ outcome.value }}
                </span>
                <span class="text-slate-400 tabular-nums dark:text-slate-500">
                    {{ share(outcome.value) }}%
                </span>
            </li>
        </ul>
    </div>
</template>
