<script setup lang="ts">
import { Link, usePage } from '@inertiajs/vue3';
import { computed, ref, watch } from 'vue';
import Icon from '../components/Icon.vue';
import type { IconName } from '../components/Icon.vue';
import { useConsole } from '../composables/useConsole';

const { shared, route } = useConsole();
const page = usePage();

interface NavItem {
    label: string;
    path: string;
    icon: IconName;
}

const nav: NavItem[] = [
    { label: 'Overview', path: '', icon: 'shield' },
    { label: 'Scans', path: 'scans', icon: 'scan' },
    { label: 'Threats', path: 'threats', icon: 'bug' },
    { label: 'Quarantine', path: 'quarantine', icon: 'lock' },
    { label: 'Policies', path: 'policies', icon: 'sliders' },
    { label: 'Scanner health', path: 'health', icon: 'activity' },
];

const current = computed(() => page.url.split('?')[0].replace(/\/$/, ''));

const isActive = (path: string): boolean => {
    const target = route(path).replace(/\/$/, '');

    return path === ''
        ? current.value === target
        : current.value.startsWith(target);
};

const sidebarOpen = ref(false);

// A navigation closes the drawer; leaving it open over the page it just
// loaded is the classic mobile-nav bug.
watch(current, () => {
    sidebarOpen.value = false;
});

const flash = computed(
    () => (page.props.flash ?? {}) as { success?: string; error?: string },
);
</script>

<template>
    <div
        class="min-h-screen bg-slate-50 text-slate-900 antialiased dark:bg-slate-950 dark:text-slate-100"
    >
        <!-- Drawer backdrop, small screens only. -->
        <div
            v-if="sidebarOpen"
            class="fixed inset-0 z-20 bg-slate-900/40 backdrop-blur-sm lg:hidden"
            @click="sidebarOpen = false"
        />

        <aside
            :class="[
                'fixed inset-y-0 left-0 z-30 flex w-60 flex-col border-r border-slate-200 bg-white transition-transform lg:translate-x-0 dark:border-slate-800 dark:bg-slate-900',
                sidebarOpen ? 'translate-x-0' : '-translate-x-full',
            ]"
        >
            <div
                class="flex h-16 items-center gap-2.5 border-b border-slate-100 px-5 dark:border-slate-800"
            >
                <span
                    class="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900"
                >
                    <Icon name="shield" :size="16" />
                </span>
                <span class="truncate text-sm leading-tight font-bold">{{
                    shared.brand
                }}</span>
            </div>

            <nav class="flex-1 space-y-0.5 overflow-y-auto p-2.5">
                <Link
                    v-for="item in nav"
                    :key="item.path"
                    :href="route(item.path)"
                    class="flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition"
                    :class="
                        isActive(item.path)
                            ? 'bg-slate-100 font-medium text-slate-900 dark:bg-slate-800 dark:text-slate-100'
                            : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/60 dark:hover:text-slate-200'
                    "
                    :aria-current="isActive(item.path) ? 'page' : undefined"
                >
                    <Icon :name="item.icon" :size="15" />
                    {{ item.label }}
                </Link>
            </nav>

            <div class="border-t border-slate-100 p-2.5 dark:border-slate-800">
                <a
                    :href="shared.backUrl"
                    class="flex items-center gap-2 rounded-md px-2.5 py-2 text-xs text-slate-500 hover:bg-slate-50 hover:text-slate-800 dark:text-slate-500 dark:hover:bg-slate-800/60 dark:hover:text-slate-300"
                >
                    <Icon name="chevron-left" :size="14" />
                    {{ shared.backLabel }}
                </a>
            </div>
        </aside>

        <!-- Full-width content column beside the fixed sidebar. No max-width
             container: a security console is tables and dense metrics, and
             they should use the whole monitor. -->
        <div class="lg:pl-60">
            <header
                class="sticky top-0 z-10 border-b border-slate-200 bg-white/85 backdrop-blur dark:border-slate-800 dark:bg-slate-900/85"
            >
                <div class="flex h-16 items-center gap-3 px-5 lg:px-8">
                    <button
                        type="button"
                        class="-ml-1 rounded-md p-1.5 text-slate-500 hover:bg-slate-100 lg:hidden dark:hover:bg-slate-800"
                        aria-label="Open navigation"
                        @click="sidebarOpen = true"
                    >
                        <Icon name="sliders" :size="18" />
                    </button>

                    <div class="min-w-0 flex-1">
                        <h1
                            class="truncate text-base font-semibold tracking-tight"
                        >
                            <slot name="title" />
                        </h1>
                        <p
                            v-if="$slots.description"
                            class="truncate text-xs text-slate-500 dark:text-slate-400"
                        >
                            <slot name="description" />
                        </p>
                    </div>

                    <slot name="actions" />
                </div>
            </header>

            <main class="px-5 py-6 lg:px-8 lg:py-8">
                <div
                    v-if="flash.success"
                    class="mb-4 flex items-start gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-300"
                    role="status"
                >
                    <Icon name="check" :size="15" class="mt-0.5 shrink-0" />
                    {{ flash.success }}
                </div>

                <div
                    v-if="flash.error"
                    class="mb-4 flex items-start gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300"
                    role="alert"
                >
                    <Icon name="alert" :size="15" class="mt-0.5 shrink-0" />
                    {{ flash.error }}
                </div>

                <slot />
            </main>
        </div>
    </div>
</template>
