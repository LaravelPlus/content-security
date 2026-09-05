<script setup lang="ts">
import { computed } from 'vue';

/**
 * Kaj se nalaga, po vrsti datoteke.
 *
 * Vodoravne palice in ne kolobar: imena vrst so dolga (`image/webp`) in ob
 * palici stojijo brez lovljenja legende. Barve so kategoricne, po stalnem
 * vrstnem redu -- filter, ki odstrani vrsto, ne sme prebarvati preostalih.
 * Vrednost stoji ob palici, ker tri od sestih barv na svetli podlagi ne
 * dosezejo 3:1 in oznaka je tista, ki jih resi.
 */
const props = defineProps<{ types: Array<{ label: string; value: number }> }>();

// Preverjeno z validatorjem palete (svetlo in temno): najhujsi sosednji par
// CVD ΔE 9.1 / 8.4, normalni vid 19.6 / 19.3.
const hues = [
    'bg-[#2a78d6] dark:bg-[#3987e5]',
    'bg-[#eb6834] dark:bg-[#d95926]',
    'bg-[#1baf7a] dark:bg-[#199e70]',
    'bg-[#eda100] dark:bg-[#c98500]',
    'bg-[#e87ba4] dark:bg-[#d55181]',
    'bg-[#008300] dark:bg-[#008300]',
];

const max = computed(() =>
    props.types.reduce((peak, type) => Math.max(peak, type.value), 0),
);
</script>

<template>
    <ul v-if="props.types.length > 0" class="space-y-2">
        <li
            v-for="(type, index) in props.types"
            :key="type.label"
            class="grid grid-cols-[minmax(0,9rem)_1fr_auto] items-center gap-3"
        >
            <span
                class="truncate font-mono text-xs text-slate-600 dark:text-slate-300"
                :title="type.label"
            >
                {{ type.label }}
            </span>

            <span
                class="h-2.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800"
            >
                <span
                    class="block h-full rounded-full"
                    :class="hues[index % hues.length]"
                    :style="{
                        width: `${max === 0 ? 0 : (type.value / max) * 100}%`,
                    }"
                />
            </span>

            <span
                class="text-xs font-semibold text-slate-900 tabular-nums dark:text-slate-100"
            >
                {{ type.value }}
            </span>
        </li>
    </ul>
</template>
