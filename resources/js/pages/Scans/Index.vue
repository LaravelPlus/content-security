<script setup lang="ts">
import { Head, router } from '@inertiajs/vue3';
import { computed, reactive, ref, watch } from 'vue';
import Icon from '../components/Icon.vue';
import Pagination from '../components/Pagination.vue';
import ScanTable from '../components/ScanTable.vue';
import { debounce } from '../composables/debounce';
import { useConsole } from '../composables/useConsole';
import SecurityAdminLayout from '../layouts/SecurityAdminLayout.vue';
import type { Paginated, Scan } from '../types';

const props = defineProps<{
    scans: Paginated<Scan>;
    filters: Record<string, string | null>;
    options: {
        statuses: string[];
        types: string[];
        levels: string[];
        scanners: string[];
        mimeTypes: string[];
    };
}>();

const { route } = useConsole();

const form = reactive({
    q: props.filters.q ?? '',
    status: props.filters.status ?? '',
    type: props.filters.type ?? '',
    scanner: props.filters.scanner ?? '',
    mime: props.filters.mime ?? '',
    level: props.filters.level ?? '',
    from: props.filters.from ?? '',
    to: props.filters.to ?? '',
});

const submit = debounce(() => {
    router.get(
        route('scans'),
        Object.fromEntries(
            Object.entries(form).filter(([, value]) => value !== ''),
        ),
        { preserveState: true, preserveScroll: true, replace: true },
    );
}, 300);

watch(form, submit);

const reset = (): void => {
    Object.keys(form).forEach((key) => {
        form[key as keyof typeof form] = '';
    });
};

/*
 * Statusi so tisto, po cemer clovek na tem zaslonu isce v devetih primerih od
 * desetih; ostalih sest spustnih menijev je za deseti. Zato so statusi cipi,
 * ostalo pa se odpre, ko je res treba.
 */
const statusLabels: Record<string, string> = {
    clean: 'Clean',
    suspicious: 'Suspicious',
    infected: 'Malware',
    quarantined: 'Quarantined',
    failed: 'Failed',
    pending: 'Pending',
    scanning: 'Scanning',
};

const showMore = ref(
    ['type', 'scanner', 'mime', 'level', 'from', 'to'].some(
        (key) => (props.filters[key] ?? '') !== '',
    ),
);

const activeExtra = computed(
    () =>
        ['type', 'scanner', 'mime', 'level', 'from', 'to'].filter(
            (key) => form[key as keyof typeof form] !== '',
        ).length,
);

const inputClass =
    'w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-slate-900 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100';
</script>

<template>
    <Head title="Scans — Content Security" />

    <SecurityAdminLayout>
        <template #title>Scans</template>
        <template #description>Every scan on record, newest first.</template>

        <div
            class="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900"
        >
            <div class="mb-3 flex flex-wrap gap-1.5">
                <button
                    type="button"
                    class="rounded-full px-3 py-1 text-xs font-medium transition focus-visible:ring-2 focus-visible:ring-slate-400 focus-visible:outline-none"
                    :class="
                        form.status === ''
                            ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                            : 'border border-slate-200 text-slate-600 hover:border-slate-300 dark:border-slate-700 dark:text-slate-300'
                    "
                    @click="form.status = ''"
                >
                    All
                </button>
                <button
                    v-for="status in props.options.statuses"
                    :key="status"
                    type="button"
                    class="rounded-full px-3 py-1 text-xs font-medium transition focus-visible:ring-2 focus-visible:ring-slate-400 focus-visible:outline-none"
                    :class="
                        form.status === status
                            ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900'
                            : 'border border-slate-200 text-slate-600 hover:border-slate-300 dark:border-slate-700 dark:text-slate-300'
                    "
                    @click="form.status = status"
                >
                    {{ statusLabels[status] ?? status }}
                </button>
            </div>

            <label class="relative block">
                <span class="sr-only"
                    >Search by filename, scan id or checksum</span
                >
                <Icon
                    name="search"
                    :size="14"
                    class="pointer-events-none absolute top-2.5 left-2.5 text-slate-400"
                />
                <input
                    v-model="form.q"
                    type="search"
                    placeholder="Filename, scan id or SHA-256…"
                    :class="[inputClass, 'pl-8']"
                />
            </label>

            <div
                v-show="showMore"
                class="mt-2 grid gap-2 sm:grid-cols-2 lg:grid-cols-4"
            >
                <label>
                    <span class="sr-only">Type</span>
                    <select v-model="form.type" :class="inputClass">
                        <option value="">All types</option>
                        <option
                            v-for="type in props.options.types"
                            :key="type"
                            :value="type"
                        >
                            {{ type }}
                        </option>
                    </select>
                </label>

                <label>
                    <span class="sr-only">Scanner</span>
                    <select v-model="form.scanner" :class="inputClass">
                        <option value="">All scanners</option>
                        <option
                            v-for="scanner in props.options.scanners"
                            :key="scanner"
                            :value="scanner"
                        >
                            {{ scanner }}
                        </option>
                    </select>
                </label>

                <label>
                    <span class="sr-only">MIME type</span>
                    <select v-model="form.mime" :class="inputClass">
                        <option value="">All MIME types</option>
                        <option
                            v-for="mime in props.options.mimeTypes"
                            :key="mime"
                            :value="mime"
                        >
                            {{ mime }}
                        </option>
                    </select>
                </label>

                <label>
                    <span class="sr-only">Threat level</span>
                    <select v-model="form.level" :class="inputClass">
                        <option value="">Any threat level</option>
                        <option
                            v-for="level in props.options.levels"
                            :key="level"
                            :value="level"
                        >
                            {{ level }}
                        </option>
                    </select>
                </label>

                <div class="flex gap-2">
                    <label class="flex-1">
                        <span class="sr-only">From date</span>
                        <input
                            v-model="form.from"
                            type="date"
                            :class="inputClass"
                        />
                    </label>
                    <label class="flex-1">
                        <span class="sr-only">To date</span>
                        <input
                            v-model="form.to"
                            type="date"
                            :class="inputClass"
                        />
                    </label>
                </div>
            </div>

            <div class="mt-2 flex items-center gap-4">
                <button
                    type="button"
                    class="inline-flex items-center gap-1 text-xs font-medium text-slate-600 hover:text-slate-900 focus-visible:ring-2 focus-visible:ring-slate-400 focus-visible:outline-none dark:text-slate-300 dark:hover:text-slate-100"
                    :aria-expanded="showMore"
                    @click="showMore = !showMore"
                >
                    <Icon
                        :name="showMore ? 'chevron-left' : 'chevron-right'"
                        :size="12"
                    />
                    {{ showMore ? 'Fewer filters' : 'More filters' }}
                    <span
                        v-if="activeExtra > 0"
                        class="rounded-full bg-slate-900 px-1.5 text-[10px] font-semibold text-white dark:bg-slate-100 dark:text-slate-900"
                        >{{ activeExtra }}</span
                    >
                </button>

                <button
                    type="button"
                    class="text-xs text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
                    @click="reset"
                >
                    Clear filters
                </button>
            </div>
        </div>

        <div class="mt-4">
            <ScanTable
                v-if="props.scans.data.length > 0"
                :scans="props.scans.data"
            />

            <p
                v-else
                class="rounded-xl border border-dashed border-slate-200 px-4 py-12 text-center text-sm text-slate-400 dark:border-slate-800 dark:text-slate-500"
            >
                No scan matches these filters.
            </p>

            <Pagination
                v-if="props.scans.meta"
                :current-page="props.scans.meta.current_page"
                :last-page="props.scans.meta.last_page"
                :total="props.scans.meta.total"
            />
        </div>
    </SecurityAdminLayout>
</template>
