<script setup lang="ts">
import { computed } from 'vue';
import { router } from '@inertiajs/vue3';
import Icon from './Icon.vue';

const props = defineProps<{
    currentPage: number;
    lastPage: number;
    total: number;
}>();

const go = (page: number): void => {
    const url = new URL(window.location.href);
    url.searchParams.set('page', String(page));
    router.get(url.toString(), {}, { preserveScroll: true, preserveState: true });
};

const canPrevious = computed(() => props.currentPage > 1);
const canNext = computed(() => props.currentPage < props.lastPage);
</script>

<template>
    <nav
        v-if="props.lastPage > 1"
        class="mt-4 flex items-center justify-between text-sm"
        aria-label="Pagination"
    >
        <p class="text-xs text-slate-500 dark:text-slate-400">
            Page {{ props.currentPage }} of {{ props.lastPage }} · {{ props.total.toLocaleString() }} record(s)
        </p>

        <div class="flex gap-1">
            <button
                type="button"
                :disabled="!canPrevious"
                class="flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 disabled:opacity-40 enabled:hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:enabled:hover:bg-slate-800"
                @click="go(props.currentPage - 1)"
            >
                <Icon name="chevron-left" :size="13" /> Previous
            </button>
            <button
                type="button"
                :disabled="!canNext"
                class="flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1.5 text-xs font-medium text-slate-700 disabled:opacity-40 enabled:hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:enabled:hover:bg-slate-800"
                @click="go(props.currentPage + 1)"
            >
                Next <Icon name="chevron-right" :size="13" />
            </button>
        </div>
    </nav>
</template>
