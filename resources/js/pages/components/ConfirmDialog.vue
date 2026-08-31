<script setup lang="ts">
import { ref, watch } from 'vue';
import Icon from './Icon.vue';

const props = withDefaults(
    defineProps<{
        open: boolean;
        title: string;
        description: string;
        confirmLabel?: string;
        tone?: 'danger' | 'default';
        processing?: boolean;
        /**
         * When set, the operator must type this exact word to proceed.
         * Reserved for the actions that cannot be undone.
         */
        requirePhrase?: string;
    }>(),
    { confirmLabel: 'Confirm', tone: 'default', processing: false },
);

const emit = defineEmits<{ confirm: []; cancel: [] }>();

const typed = ref('');

watch(
    () => props.open,
    (open) => {
        if (open) {
            typed.value = '';
        }
    },
);

const canConfirm = () =>
    !props.processing &&
    (!props.requirePhrase || typed.value.trim() === props.requirePhrase);
</script>

<template>
    <Teleport to="body">
        <div
            v-if="props.open"
            class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 p-4"
            role="dialog"
            aria-modal="true"
            @keydown.esc="emit('cancel')"
        >
            <div
                class="w-full max-w-md rounded-lg border border-slate-200 bg-white p-5 shadow-xl dark:border-slate-800 dark:bg-slate-900"
            >
                <div class="flex items-start gap-3">
                    <span
                        class="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full"
                        :class="
                            props.tone === 'danger'
                                ? 'bg-red-50 text-red-600 dark:bg-red-500/10 dark:text-red-400'
                                : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'
                        "
                    >
                        <Icon name="alert" :size="16" />
                    </span>
                    <div class="min-w-0">
                        <h2
                            class="text-sm font-semibold text-slate-900 dark:text-slate-100"
                        >
                            {{ props.title }}
                        </h2>
                        <p
                            class="mt-1 text-xs text-slate-600 dark:text-slate-400"
                        >
                            {{ props.description }}
                        </p>
                    </div>
                </div>

                <slot />

                <div v-if="props.requirePhrase" class="mt-4">
                    <label
                        class="block text-xs font-medium text-slate-700 dark:text-slate-300"
                    >
                        Type
                        <span class="font-mono font-semibold">{{
                            props.requirePhrase
                        }}</span>
                        to confirm
                    </label>
                    <input
                        v-model="typed"
                        type="text"
                        autocomplete="off"
                        class="mt-1 w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-slate-900 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
                    />
                </div>

                <div class="mt-5 flex justify-end gap-2">
                    <button
                        type="button"
                        class="rounded-md px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
                        @click="emit('cancel')"
                    >
                        Cancel
                    </button>
                    <button
                        type="button"
                        :disabled="!canConfirm()"
                        class="rounded-md px-3 py-1.5 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-40"
                        :class="
                            props.tone === 'danger'
                                ? 'bg-red-600 hover:bg-red-700'
                                : 'bg-slate-900 hover:bg-slate-800 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-white'
                        "
                        @click="emit('confirm')"
                    >
                        {{ props.processing ? 'Working…' : props.confirmLabel }}
                    </button>
                </div>
            </div>
        </div>
    </Teleport>
</template>
