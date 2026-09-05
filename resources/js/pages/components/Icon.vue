<script setup lang="ts">
/**
 * Inline SVG icons on a 24px grid.
 *
 * Deliberately not a dependency: a reusable package should not force an icon
 * library on every host that installs it, and this set is eleven paths. No
 * emoji — an emoji renders differently on every platform and carries no
 * accessible name.
 */
const props = withDefaults(
    defineProps<{
        name: IconName;
        size?: number | string;
        title?: string;
    }>(),
    { size: 16 },
);

export type IconName =
    | 'shield'
    | 'shield-alert'
    | 'scan'
    | 'bug'
    | 'lock'
    | 'sliders'
    | 'activity'
    | 'search'
    | 'chevron-right'
    | 'chevron-left'
    | 'check'
    | 'x'
    | 'alert'
    | 'clock'
    | 'refresh'
    | 'trash'
    | 'unlock'
    | 'file'
    | 'image'
    | 'archive'
    | 'text'
    | 'pdf'
    | 'external';

const paths: Record<IconName, string[]> = {
    shield: ['M12 3 4 6v6c0 4.4 3.4 8.2 8 9 4.6-.8 8-4.6 8-9V6l-8-3Z'],
    'shield-alert': [
        'M12 3 4 6v6c0 4.4 3.4 8.2 8 9 4.6-.8 8-4.6 8-9V6l-8-3Z',
        'M12 8v4',
        'M12 16h.01',
    ],
    scan: [
        'M3 7V5a2 2 0 0 1 2-2h2',
        'M17 3h2a2 2 0 0 1 2 2v2',
        'M21 17v2a2 2 0 0 1-2 2h-2',
        'M7 21H5a2 2 0 0 1-2-2v-2',
        'M3 12h18',
    ],
    bug: [
        'M8 6a4 4 0 0 1 8 0',
        'M6 10h12v4a6 6 0 0 1-12 0v-4Z',
        'M3 13h3',
        'M18 13h3',
        'M4 6l2 2',
        'M20 6l-2 2',
        'M4 19l2-2',
        'M20 19l-2-2',
    ],
    lock: ['M5 11h14v10H5z', 'M8 11V7a4 4 0 0 1 8 0v4'],
    sliders: [
        'M4 6h16',
        'M4 12h16',
        'M4 18h16',
        'M9 4v4',
        'M15 10v4',
        'M7 16v4',
    ],
    activity: ['M3 12h4l3 8 4-16 3 8h4'],
    search: ['M11 19a8 8 0 1 1 0-16 8 8 0 0 1 0 16Z', 'M21 21l-4.3-4.3'],
    'chevron-right': ['M9 6l6 6-6 6'],
    'chevron-left': ['M15 6l-6 6 6 6'],
    check: ['M4 12l5 5L20 6'],
    x: ['M6 6l12 12', 'M18 6L6 18'],
    alert: ['M12 3l9 16H3l9-16Z', 'M12 9v4', 'M12 17h.01'],
    clock: ['M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18Z', 'M12 7v5l3 2'],
    refresh: ['M21 12a9 9 0 1 1-3-6.7', 'M21 4v5h-5'],
    trash: [
        'M4 7h16',
        'M9 7V5h6v2',
        'M6 7l1 13h10l1-13',
        'M10 11v6',
        'M14 11v6',
    ],
    unlock: ['M5 11h14v10H5z', 'M8 11V7a4 4 0 0 1 7.5-2'],
    file: ['M6 3h7l5 5v13H6z', 'M13 3v5h5'],
    image: [
        'M4 5h16v14H4z',
        'M4 16l4.5-4.5 3 3L15 11l5 5',
        'M9 9.5a1 1 0 1 1-2 0 1 1 0 0 1 2 0Z',
    ],
    archive: ['M3 7h18v13H3z', 'M3 7l2-3h14l2 3', 'M10 12h4'],
    text: ['M6 3h7l5 5v13H6z', 'M13 3v5h5', 'M9 13h6', 'M9 17h6'],
    pdf: [
        'M6 3h7l5 5v13H6z',
        'M13 3v5h5',
        'M9 14h1.5a1.5 1.5 0 0 1 0 3H9v-3Z',
        'M14 14v3',
    ],
    external: [
        'M14 4h6v6',
        'M20 4l-8 8',
        'M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5',
    ],
};
</script>

<template>
    <svg
        :width="props.size"
        :height="props.size"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.75"
        stroke-linecap="round"
        stroke-linejoin="round"
        :aria-hidden="props.title ? undefined : true"
        :role="props.title ? 'img' : undefined"
        :aria-label="props.title"
    >
        <title v-if="props.title">{{ props.title }}</title>
        <path v-for="(d, index) in paths[props.name]" :key="index" :d="d" />
    </svg>
</template>
