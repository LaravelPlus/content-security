<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue';
import Icon from './Icon.vue';
import type { IconName } from './Icon.vue';

/**
 * Svetlo, temno ali po sistemu.
 *
 * Konzola je imela temne razlicice povsod, a jih ni videl nihce: gostitelj
 * temo pozna, a je nikoli ne postavi, zato je razred `dark` ostal nenapisan.
 * Preklopnik ga postavi sam -- in ga ob odhodu iz konzole pospravi, ker so
 * strani gostitelja pisane samo za svetlo.
 *
 * Izbira se hrani pod svojim kljucem, ne pod gostiteljevim: konzola ne sme
 * cez noc obrniti teme aplikaciji, ki je za to ni prosila.
 */
type Mode = 'light' | 'dark' | 'auto';

const STORAGE_KEY = 'content-security.appearance';

const modes: Array<{ value: Mode; label: string; icon: IconName }> = [
    { value: 'light', label: 'Light', icon: 'sun' },
    { value: 'dark', label: 'Dark', icon: 'moon' },
    { value: 'auto', label: 'Match system', icon: 'monitor' },
];

const mode = ref<Mode>('auto');

const prefersDark = (): boolean =>
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches;

const apply = (value: Mode): void => {
    const dark = value === 'dark' || (value === 'auto' && prefersDark());

    document.documentElement.classList.toggle('dark', dark);
};

const onSystemChange = (): void => {
    if (mode.value === 'auto') {
        apply('auto');
    }
};

onMounted(() => {
    const stored = localStorage.getItem(STORAGE_KEY) as Mode | null;

    if (stored === 'light' || stored === 'dark' || stored === 'auto') {
        mode.value = stored;
    }

    apply(mode.value);
    window
        .matchMedia('(prefers-color-scheme: dark)')
        .addEventListener('change', onSystemChange);
});

onBeforeUnmount(() => {
    // Strani gostitelja so pisane za svetlo; temo pustimo za sabo, kot smo jo
    // nasli.
    document.documentElement.classList.remove('dark');
    window
        .matchMedia('(prefers-color-scheme: dark)')
        .removeEventListener('change', onSystemChange);
});

watch(mode, (value) => {
    localStorage.setItem(STORAGE_KEY, value);
    apply(value);
});
</script>

<template>
    <div
        class="flex rounded-lg border border-slate-200 bg-white p-0.5 dark:border-slate-700 dark:bg-slate-900"
        role="group"
        aria-label="Theme"
    >
        <button
            v-for="option in modes"
            :key="option.value"
            type="button"
            class="rounded-md p-1.5 transition focus-visible:ring-2 focus-visible:ring-slate-400 focus-visible:outline-none"
            :class="
                mode === option.value
                    ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                    : 'text-slate-400 hover:text-slate-700 dark:text-slate-500 dark:hover:text-slate-300'
            "
            :aria-pressed="mode === option.value"
            :title="option.label"
            @click="mode = option.value"
        >
            <span class="sr-only">{{ option.label }}</span>
            <Icon :name="option.icon" :size="14" />
        </button>
    </div>
</template>
