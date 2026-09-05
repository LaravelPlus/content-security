<script setup lang="ts">
import { Head, router } from '@inertiajs/vue3';
import { reactive, watch } from 'vue';
import EmptyState from '../components/EmptyState.vue';
import Icon from '../components/Icon.vue';
import Pagination from '../components/Pagination.vue';
import ThreatBadge from '../components/ThreatBadge.vue';
import { debounce } from '../composables/debounce';
import {
    formatDate,
    formatNumber,
    useConsole,
} from '../composables/useConsole';
import { explainThreat } from '../explanations';
import SecurityAdminLayout from '../layouts/SecurityAdminLayout.vue';
import type { AggregatedThreat, Paginated } from '../types';

const props = defineProps<{
    threats: Paginated<AggregatedThreat>;
    filters: Record<string, string | null>;
    options: { levels: string[] };
}>();

const { route } = useConsole();

const form = reactive({
    q: props.filters.q ?? '',
    level: props.filters.level ?? '',
    from: props.filters.from ?? '',
});

const submit = debounce(() => {
    router.get(
        route('threats'),
        Object.fromEntries(
            Object.entries(form).filter(([, value]) => value !== ''),
        ),
        { preserveState: true, preserveScroll: true, replace: true },
    );
}, 300);

watch(form, submit);

const inputClass =
    'w-full rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-slate-900 focus:border-slate-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100';
</script>

<template>
    <Head title="Threats — Content Security" />

    <SecurityAdminLayout>
        <template #title>Threats</template>
        <template #description>
            Findings grouped by signature — forty occurrences of one thing is
            one thing to look at.
        </template>

        <div
            class="grid gap-2 rounded-lg border border-slate-200 bg-white p-3 sm:grid-cols-3 dark:border-slate-800 dark:bg-slate-900"
        >
            <label class="relative">
                <span class="sr-only">Search threats</span>
                <Icon
                    name="search"
                    :size="14"
                    class="pointer-events-none absolute top-2.5 left-2.5 text-slate-400"
                />
                <input
                    v-model="form.q"
                    type="search"
                    placeholder="Signature name…"
                    :class="[inputClass, 'pl-8']"
                />
            </label>

            <label>
                <span class="sr-only">Severity</span>
                <select v-model="form.level" :class="inputClass">
                    <option value="">Any severity</option>
                    <option
                        v-for="level in props.options.levels"
                        :key="level"
                        :value="level"
                    >
                        {{ level }}
                    </option>
                </select>
            </label>

            <label>
                <span class="sr-only">Seen since</span>
                <input v-model="form.from" type="date" :class="inputClass" />
            </label>
        </div>

        <div class="mt-4">
            <EmptyState
                v-if="props.threats.data.length === 0"
                icon="shield"
                title="No threats recorded"
                description="Nothing has tripped a security check in this period."
            />

            <div
                v-else
                class="overflow-x-auto rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900"
            >
                <table
                    class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800"
                >
                    <thead>
                        <tr
                            class="text-left text-xs text-slate-500 dark:text-slate-400"
                        >
                            <th scope="col" class="px-4 py-2.5 font-semibold">
                                Threat
                            </th>
                            <th scope="col" class="px-4 py-2.5 font-semibold">
                                Severity
                            </th>
                            <th scope="col" class="px-4 py-2.5 font-semibold">
                                Scanner
                            </th>
                            <th
                                scope="col"
                                class="px-4 py-2.5 text-right font-semibold"
                            >
                                Occurrences
                            </th>
                            <th scope="col" class="px-4 py-2.5 font-semibold">
                                First seen
                            </th>
                            <th scope="col" class="px-4 py-2.5 font-semibold">
                                Last seen
                            </th>
                        </tr>
                    </thead>
                    <tbody
                        class="divide-y divide-slate-100 dark:divide-slate-800/70"
                    >
                        <tr
                            v-for="threat in props.threats.data"
                            :key="`${threat.name}-${threat.level}-${threat.source}`"
                            class="hover:bg-slate-50 dark:hover:bg-slate-800/40"
                        >
                            <td class="px-4 py-2.5">
                                <p class="font-mono text-xs">
                                    {{ threat.name }}
                                </p>
                                <!-- Ime podpisa je za tistega, ki ga ni pisal, samo niz. -->
                                <p
                                    class="mt-0.5 max-w-md text-xs text-slate-500 dark:text-slate-400"
                                >
                                    {{
                                        explainThreat(
                                            threat.name,
                                            threat.source,
                                        )
                                    }}
                                </p>
                            </td>
                            <td class="px-4 py-2.5">
                                <ThreatBadge :level="threat.level" />
                            </td>
                            <td
                                class="px-4 py-2.5 text-slate-600 dark:text-slate-400"
                            >
                                {{ threat.source }}
                            </td>
                            <td
                                class="px-4 py-2.5 text-right font-semibold tabular-nums"
                            >
                                {{ formatNumber(threat.occurrences) }}
                            </td>
                            <td
                                class="px-4 py-2.5 whitespace-nowrap text-slate-600 dark:text-slate-400"
                            >
                                {{ formatDate(threat.first_seen) }}
                            </td>
                            <td
                                class="px-4 py-2.5 whitespace-nowrap text-slate-600 dark:text-slate-400"
                            >
                                {{ formatDate(threat.last_seen) }}
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <Pagination
                v-if="props.threats.current_page && props.threats.last_page"
                :current-page="props.threats.current_page"
                :last-page="props.threats.last_page"
                :total="props.threats.total ?? 0"
            />
        </div>
    </SecurityAdminLayout>
</template>
