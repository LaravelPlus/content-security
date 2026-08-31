<script setup lang="ts">
import Icon, { type IconName } from './Icon.vue';

withDefaults(
    defineProps<{ title: string; description?: string; icon?: IconName }>(),
    { icon: 'scan' },
);
</script>

<template>
    <div
        class="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-300 px-6 py-14 text-center dark:border-slate-700"
    >
        <Icon :name="icon" :size="28" class="text-slate-300 dark:text-slate-600" />
        <p class="mt-3 text-sm font-medium text-slate-700 dark:text-slate-200">
            {{ title }}
        </p>
        <p
            v-if="description"
            class="mt-1 max-w-sm text-xs text-slate-500 dark:text-slate-400"
        >
            {{ description }}
        </p>
        <slot />
    </div>
</template>
