<script setup lang="ts">
import { ref } from 'vue';
import { Head, router, useForm } from '@inertiajs/vue3';
import SecurityAdminLayout from '../layouts/SecurityAdminLayout.vue';
import StatusBadge from '../components/StatusBadge.vue';
import ThreatBadge from '../components/ThreatBadge.vue';
import EmptyState from '../components/EmptyState.vue';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import Pagination from '../components/Pagination.vue';
import Icon from '../components/Icon.vue';
import { formatBytes, formatDate, useConsole } from '../composables/useConsole';
import type { Paginated, Scan } from '../types';

const props = defineProps<{
    items: Paginated<Scan>;
    retentionDays: number;
}>();

const { route } = useConsole();

const releasing = ref<Scan | null>(null);
const deleting = ref<Scan | null>(null);

const releaseForm = useForm({ disk: 'local', path: '', override: false, reason: '' });

const rescan = (scan: Scan): void => {
    router.post(route(`quarantine/${scan.id}/rescan`), {}, { preserveScroll: true });
};

const submitRelease = (): void => {
    if (!releasing.value) return;

    releaseForm.post(route(`quarantine/${releasing.value.id}/release`), {
        preserveScroll: true,
        onSuccess: () => {
            releasing.value = null;
            releaseForm.reset();
        },
    });
};

const confirmDelete = (): void => {
    if (!deleting.value) return;

    router.delete(route(`quarantine/${deleting.value.id}`), {
        preserveScroll: true,
        onFinish: () => {
            deleting.value = null;
        },
    });
};

const inputClass =
    'w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-slate-900 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100';
</script>

<template>
    <Head title="Quarantine — Content Security" />

    <SecurityAdminLayout>
        <template #title>Quarantine</template>
        <template #description>
            Files held out of normal storage. Deleted automatically after {{ props.retentionDays }} days.
        </template>

        <EmptyState
            v-if="props.items.data.length === 0"
            icon="lock"
            title="Quarantine is empty"
            description="Files rejected by a policy with quarantine enabled are held here for review."
        />

        <div v-else class="space-y-3">
            <article
                v-for="item in props.items.data"
                :key="item.id"
                class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
            >
                <div class="flex flex-wrap items-start justify-between gap-3">
                    <div class="min-w-0">
                        <div class="flex items-center gap-2">
                            <Icon name="file" :size="15" class="shrink-0 text-slate-400" />
                            <p class="truncate font-medium" :title="item.subject">{{ item.subject }}</p>
                            <StatusBadge :status="item.status" />
                        </div>
                        <p class="mt-1 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                            {{ item.short_id }} · {{ formatBytes(item.size) }} ·
                            {{ item.detected_mime ?? 'unknown type' }} · {{ formatDate(item.created_at) }}
                        </p>
                    </div>

                    <div class="flex shrink-0 gap-2">
                        <button
                            type="button"
                            class="flex items-center gap-1.5 rounded-md border border-slate-200 px-2.5 py-1.5 text-xs font-medium hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
                            @click="rescan(item)"
                        >
                            <Icon name="refresh" :size="13" /> Rescan
                        </button>
                        <button
                            type="button"
                            class="flex items-center gap-1.5 rounded-md border border-slate-200 px-2.5 py-1.5 text-xs font-medium hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
                            @click="releasing = item"
                        >
                            <Icon name="unlock" :size="13" /> Release
                        </button>
                        <button
                            type="button"
                            class="flex items-center gap-1.5 rounded-md border border-red-200 px-2.5 py-1.5 text-xs font-medium text-red-700 hover:bg-red-50 dark:border-red-500/30 dark:text-red-400 dark:hover:bg-red-500/10"
                            @click="deleting = item"
                        >
                            <Icon name="trash" :size="13" /> Delete
                        </button>
                    </div>
                </div>

                <ul v-if="item.threats && item.threats.length > 0" class="mt-3 flex flex-wrap gap-2">
                    <li
                        v-for="threat in item.threats"
                        :key="threat.id ?? threat.name"
                        class="flex items-center gap-1.5 rounded border border-slate-200 px-2 py-1 text-xs dark:border-slate-800"
                    >
                        <ThreatBadge :level="threat.level" />
                        <span class="font-mono">{{ threat.name }}</span>
                    </li>
                </ul>
            </article>

            <Pagination
                v-if="props.items.meta"
                :current-page="props.items.meta.current_page"
                :last-page="props.items.meta.last_page"
                :total="props.items.meta.total"
            />
        </div>

        <ConfirmDialog
            :open="releasing !== null"
            title="Release this file?"
            description="The file is rescanned first and released only if the new scan comes back clean. Choose where it should be written."
            confirm-label="Release"
            :processing="releaseForm.processing"
            @cancel="releasing = null"
            @confirm="submitRelease"
        >
            <div class="mt-4 space-y-3">
                <label class="block">
                    <span class="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">Target disk</span>
                    <input v-model="releaseForm.disk" type="text" :class="inputClass" />
                </label>

                <label class="block">
                    <span class="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">Target path</span>
                    <input
                        v-model="releaseForm.path"
                        type="text"
                        placeholder="uploads/2026/invoice.pdf"
                        :class="inputClass"
                    />
                </label>

                <label class="flex items-start gap-2">
                    <input v-model="releaseForm.override" type="checkbox" class="mt-0.5" />
                    <span class="text-xs text-slate-600 dark:text-slate-400">
                        Release even if the rescan is not clean.
                        <strong class="text-red-600 dark:text-red-400">This is recorded in the audit log.</strong>
                    </span>
                </label>

                <label v-if="releaseForm.override" class="block">
                    <span class="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">
                        Reason for the override
                    </span>
                    <input v-model="releaseForm.reason" type="text" :class="inputClass" />
                </label>

                <p v-if="releaseForm.errors.path" class="text-xs text-red-600">{{ releaseForm.errors.path }}</p>
                <p v-if="releaseForm.errors.reason" class="text-xs text-red-600">{{ releaseForm.errors.reason }}</p>
            </div>
        </ConfirmDialog>

        <ConfirmDialog
            :open="deleting !== null"
            tone="danger"
            title="Permanently delete this file?"
            description="The file is erased from the quarantine disk. Its scan record is kept, so the audit trail survives."
            confirm-label="Delete permanently"
            require-phrase="DELETE"
            @cancel="deleting = null"
            @confirm="confirmDelete"
        />
    </SecurityAdminLayout>
</template>
