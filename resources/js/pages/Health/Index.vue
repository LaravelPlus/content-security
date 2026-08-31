<script setup lang="ts">
import { ref } from 'vue';
import { Head, router } from '@inertiajs/vue3';
import SecurityAdminLayout from '../layouts/SecurityAdminLayout.vue';
import ScannerHealthCard from '../components/ScannerHealthCard.vue';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import Icon from '../components/Icon.vue';
import { formatDate, useConsole } from '../composables/useConsole';
import type { ScannerHealth } from '../types';

const props = defineProps<{
    scanners: ScannerHealth[];
    lastScanAt: string | null;
    pipeline: {
        file: Array<{ key: string; label: string }>;
        text: Array<{ key: string; label: string }>;
    };
    extensions: Record<string, boolean>;
}>();

const { route } = useConsole();

const testing = ref(false);
const confirmTest = ref(false);

const runTest = (): void => {
    testing.value = true;

    router.post(
        route('health/test'),
        {},
        {
            preserveScroll: true,
            onFinish: () => {
                testing.value = false;
                confirmTest.value = false;
            },
        },
    );
};
</script>

<template>
    <Head title="Scanner health — Content Security" />

    <SecurityAdminLayout>
        <template #title>Scanner health</template>
        <template #description>Engine state, the active pipeline, and the PHP extensions it depends on.</template>

        <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
            <p class="text-xs text-slate-500 dark:text-slate-400">
                Last scan: {{ formatDate(props.lastScanAt) }}
            </p>

            <button
                type="button"
                class="flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-white"
                @click="confirmTest = true"
            >
                <Icon name="activity" :size="13" /> Test scanner
            </button>
        </div>

        <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <ScannerHealthCard
                v-for="scanner in props.scanners"
                :key="scanner.scanner"
                :health="scanner"
            />
        </div>

        <div class="mt-6 grid gap-5 lg:grid-cols-3">
            <section class="rounded-lg border border-slate-200 bg-white p-4 lg:col-span-2 dark:border-slate-800 dark:bg-slate-900">
                <h2 class="text-sm font-semibold">Active pipeline</h2>
                <p class="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    Checks run in this order. Cheap structural checks come first so an obviously bad
                    upload never reaches the malware engine.
                </p>

                <div class="mt-4">
                    <p class="mb-2 text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Files</p>
                    <ol class="flex flex-wrap items-center gap-1.5">
                        <li v-for="(check, index) in props.pipeline.file" :key="check.key" class="flex items-center gap-1.5">
                            <span class="rounded border border-slate-200 px-2 py-1 text-xs dark:border-slate-700">
                                {{ check.label }}
                            </span>
                            <Icon
                                v-if="index < props.pipeline.file.length - 1"
                                name="chevron-right"
                                :size="12"
                                class="text-slate-300 dark:text-slate-600"
                            />
                        </li>
                    </ol>
                </div>

                <div class="mt-4">
                    <p class="mb-2 text-[11px] uppercase tracking-wider text-slate-500 dark:text-slate-400">Text</p>
                    <ol class="flex flex-wrap items-center gap-1.5">
                        <li v-for="(check, index) in props.pipeline.text" :key="check.key" class="flex items-center gap-1.5">
                            <span class="rounded border border-slate-200 px-2 py-1 text-xs dark:border-slate-700">
                                {{ check.label }}
                            </span>
                            <Icon
                                v-if="index < props.pipeline.text.length - 1"
                                name="chevron-right"
                                :size="12"
                                class="text-slate-300 dark:text-slate-600"
                            />
                        </li>
                    </ol>
                </div>
            </section>

            <section class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
                <h2 class="text-sm font-semibold">PHP extensions</h2>
                <ul class="mt-3 space-y-2">
                    <li
                        v-for="(loaded, name) in props.extensions"
                        :key="name"
                        class="flex items-center justify-between text-xs"
                    >
                        <span class="font-mono">ext-{{ name }}</span>
                        <span
                            class="flex items-center gap-1 font-medium"
                            :class="loaded ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'"
                        >
                            <Icon :name="loaded ? 'check' : 'alert'" :size="12" />
                            {{ loaded ? 'loaded' : 'missing' }}
                        </span>
                    </li>
                </ul>
                <p class="mt-3 text-[11px] leading-relaxed text-slate-500 dark:text-slate-400">
                    Without <span class="font-mono">ext-zip</span> archives cannot be inspected; without
                    <span class="font-mono">ext-gd</span> images cannot be decoded or re-encoded. Both
                    checks report as unavailable rather than passing silently.
                </p>
            </section>
        </div>

        <ConfirmDialog
            :open="confirmTest"
            title="Send the EICAR test file?"
            description="EICAR is the industry's standard harmless test string — 68 printable characters that every engine is required to flag and which do nothing if executed. It proves the scanner is reachable and actually matching."
            confirm-label="Run test"
            :processing="testing"
            @cancel="confirmTest = false"
            @confirm="runTest"
        />
    </SecurityAdminLayout>
</template>
