<script setup lang="ts">
import { computed, reactive, watch } from 'vue';
import { router, useForm } from '@inertiajs/vue3';
import Icon from './Icon.vue';
import ConfirmDialog from './ConfirmDialog.vue';
import { formatBytes, useConsole } from '../composables/useConsole';
import { ref } from 'vue';

const props = defineProps<{
    policy: Record<string, any>;
    type: 'file' | 'text';
    isDefault: boolean;
    editable: boolean;
    limits: { maxSizeCeiling: number; forbiddenExtensions: string[] };
    checkLabels: Record<string, string>;
}>();

const { route } = useConsole();

const open = ref(false);
const resetting = ref(false);

const form = useForm<Record<string, any>>({
    type: props.type,
    label: props.policy.label,
    max_size: props.policy.max_size ?? 0,
    max_length: props.policy.max_length ?? 0,
    extensions: (props.policy.extensions ?? []).join(', '),
    mime_types: (props.policy.mime_types ?? []).join(', '),
    on_threat: props.policy.on_threat ?? 'quarantine',
    checks: { ...(props.policy.checks ?? {}) },
    note: '',
});

// MB in the form, bytes on the wire — nobody wants to type 26214400.
const sizeMb = computed({
    get: () => Math.round(((form.max_size as number) / 1048576) * 100) / 100,
    set: (value: number) => {
        form.max_size = Math.round(value * 1048576);
    },
});

const forbiddenTyped = computed(() => {
    const typed = String(form.extensions)
        .split(',')
        .map((e) => e.trim().replace(/^\./, '').toLowerCase())
        .filter(Boolean);

    return typed.filter((e) => props.limits.forbiddenExtensions.includes(e));
});

const submit = (): void => {
    form
        .transform((data) => {
            const payload: Record<string, unknown> = {
                type: props.type,
                label: data.label,
                checks: data.checks,
                note: data.note || null,
            };

            if (props.type === 'file') {
                payload.max_size = data.max_size;
                payload.on_threat = data.on_threat;
                payload.extensions = String(data.extensions)
                    .split(',')
                    .map((e: string) => e.trim().replace(/^\./, ''))
                    .filter(Boolean);
                payload.mime_types = String(data.mime_types)
                    .split(',')
                    .map((m: string) => m.trim())
                    .filter(Boolean);
            } else {
                payload.max_length = data.max_length;
            }

            return payload;
        })
        .put(route(`policies/${props.policy.name}`), {
            preserveScroll: true,
            onSuccess: () => {
                open.value = false;
                form.note = '';
            },
        });
};

const reset = (): void => {
    router.post(
        route(`policies/${props.policy.name}/reset`),
        { type: props.type },
        {
            preserveScroll: true,
            onFinish: () => {
                resetting.value = false;
            },
        },
    );
};

const inputClass =
    'w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-slate-900 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100';
</script>

<template>
    <article class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
        <div class="flex items-start justify-between gap-3">
            <div class="min-w-0">
                <h3 class="flex items-center gap-2 text-sm font-semibold">
                    {{ props.policy.label }}
                    <span
                        v-if="props.isDefault"
                        class="rounded bg-slate-900 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-white dark:bg-slate-100 dark:text-slate-900"
                    >
                        default
                    </span>
                    <span
                        class="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase"
                        :class="
                            props.policy.source === 'database'
                                ? 'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300'
                                : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400'
                        "
                        :title="
                            props.policy.source === 'database'
                                ? 'Overridden at runtime — differs from the config baseline'
                                : 'Straight from config/content-security.php'
                        "
                    >
                        {{ props.policy.source === 'database' ? 'overridden' : 'config' }}
                    </span>
                </h3>
                <p class="font-mono text-[11px] text-slate-500 dark:text-slate-400">{{ props.policy.name }}</p>
            </div>

            <div v-if="props.editable" class="flex shrink-0 gap-1.5">
                <button
                    type="button"
                    class="flex items-center gap-1.5 rounded-md border border-slate-200 px-2 py-1 text-xs font-medium hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
                    @click="open = !open"
                >
                    <Icon name="sliders" :size="12" /> {{ open ? 'Close' : 'Edit' }}
                </button>
                <button
                    v-if="props.policy.source === 'database'"
                    type="button"
                    class="flex items-center gap-1.5 rounded-md border border-slate-200 px-2 py-1 text-xs font-medium hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
                    @click="resetting = true"
                >
                    <Icon name="refresh" :size="12" /> Reset
                </button>
            </div>
        </div>

        <!-- Read-only summary -->
        <dl v-if="!open" class="mt-3 space-y-2 text-xs">
            <div v-if="props.type === 'file'" class="flex justify-between gap-3">
                <dt class="text-slate-500 dark:text-slate-400">Maximum size</dt>
                <dd class="font-medium tabular-nums">{{ formatBytes(props.policy.max_size) }}</dd>
            </div>
            <div v-else class="flex justify-between gap-3">
                <dt class="text-slate-500 dark:text-slate-400">Maximum length</dt>
                <dd class="font-medium tabular-nums">{{ props.policy.max_length?.toLocaleString() }} characters</dd>
            </div>
            <div v-if="props.type === 'file'" class="flex justify-between gap-3">
                <dt class="text-slate-500 dark:text-slate-400">On threat</dt>
                <dd class="font-medium capitalize">{{ props.policy.on_threat }}</dd>
            </div>
            <div v-if="props.type === 'file'">
                <dt class="mb-1 text-slate-500 dark:text-slate-400">Allowed extensions</dt>
                <dd class="flex flex-wrap gap-1">
                    <span
                        v-for="extension in props.policy.extensions"
                        :key="extension"
                        class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] dark:bg-slate-800"
                    >
                        .{{ extension }}
                    </span>
                </dd>
            </div>
        </dl>

        <!-- Editor -->
        <form v-else class="mt-4 space-y-3" @submit.prevent="submit">
            <label class="block">
                <span class="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">Label</span>
                <input v-model="form.label" type="text" :class="inputClass" />
            </label>

            <label v-if="props.type === 'file'" class="block">
                <span class="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">
                    Maximum size (MB) — ceiling {{ formatBytes(props.limits.maxSizeCeiling) }}
                </span>
                <input v-model.number="sizeMb" type="number" min="0.001" step="0.5" :class="inputClass" />
                <span v-if="form.errors.max_size" class="mt-1 block text-xs text-red-600">{{ form.errors.max_size }}</span>
            </label>

            <label v-else class="block">
                <span class="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">Maximum length</span>
                <input v-model.number="form.max_length" type="number" min="1" :class="inputClass" />
                <span v-if="form.errors.max_length" class="mt-1 block text-xs text-red-600">{{ form.errors.max_length }}</span>
            </label>

            <template v-if="props.type === 'file'">
                <label class="block">
                    <span class="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">
                        Allowed extensions (comma separated)
                    </span>
                    <textarea v-model="form.extensions" rows="2" :class="inputClass" />
                    <span v-if="form.errors.extensions" class="mt-1 block text-xs text-red-600">
                        {{ form.errors.extensions }}
                    </span>
                </label>

                <p
                    v-if="forbiddenTyped.length > 0"
                    class="flex items-start gap-1.5 rounded border border-red-200 bg-red-50 px-2 py-1.5 text-xs text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300"
                >
                    <Icon name="alert" :size="13" class="mt-0.5 shrink-0" />
                    <span>
                        <strong>.{{ forbiddenTyped.join(', .') }}</strong> are server-executable and cannot be
                        allowed from here. They are rejected on save — change
                        <span class="font-mono">forbidden_extensions</span> in config if you truly intend it.
                    </span>
                </p>

                <label class="block">
                    <span class="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">
                        Allowed MIME types (comma separated, blank = derive from extensions)
                    </span>
                    <textarea v-model="form.mime_types" rows="2" :class="inputClass" />
                </label>

                <label class="block">
                    <span class="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">Failure behaviour</span>
                    <select v-model="form.on_threat" :class="inputClass">
                        <option value="quarantine">Quarantine — keep the file for review</option>
                        <option value="reject">Reject — refuse and keep nothing</option>
                    </select>
                </label>
            </template>

            <fieldset>
                <legend class="mb-1.5 text-xs font-medium text-slate-700 dark:text-slate-300">Checks</legend>
                <div class="grid grid-cols-2 gap-1.5">
                    <label
                        v-for="(enabled, key) in form.checks"
                        :key="key"
                        class="flex items-center gap-2 text-xs"
                    >
                        <input v-model="form.checks[key]" type="checkbox" />
                        {{ props.checkLabels[key] ?? key }}
                    </label>
                </div>
                <p
                    v-if="form.checks.malware === false"
                    class="mt-2 flex items-start gap-1.5 rounded border border-amber-200 bg-amber-50 px-2 py-1.5 text-xs text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300"
                >
                    <Icon name="alert" :size="13" class="mt-0.5 shrink-0" />
                    With the malware check off, files under this policy are never sent to the engine.
                </p>
            </fieldset>

            <label class="block">
                <span class="mb-1 block text-xs font-medium text-slate-700 dark:text-slate-300">
                    Note for the audit log
                </span>
                <input v-model="form.note" type="text" placeholder="Why this change?" :class="inputClass" />
            </label>

            <div class="flex justify-end gap-2 pt-1">
                <button
                    type="button"
                    class="rounded-md px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
                    @click="open = false"
                >
                    Cancel
                </button>
                <button
                    type="submit"
                    :disabled="form.processing"
                    class="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-semibold text-white disabled:opacity-40 dark:bg-slate-100 dark:text-slate-900"
                >
                    {{ form.processing ? 'Saving…' : 'Save policy' }}
                </button>
            </div>
        </form>

        <ConfirmDialog
            :open="resetting"
            title="Reset to the config baseline?"
            description="The runtime override is deleted and this policy goes back to whatever config/content-security.php says. Recorded in the audit log."
            confirm-label="Reset"
            @cancel="resetting = false"
            @confirm="reset"
        />
    </article>
</template>
