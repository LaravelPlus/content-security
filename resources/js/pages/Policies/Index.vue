<script setup lang="ts">
import { Head } from '@inertiajs/vue3';
import Icon from '../components/Icon.vue';
import PolicyEditor from '../components/PolicyEditor.vue';
import SecurityAdminLayout from '../layouts/SecurityAdminLayout.vue';
import type { FilePolicy, TextPolicyShape } from '../types';

const props = defineProps<{
    filePolicies: FilePolicy[];
    textPolicies: TextPolicyShape[];
    defaults: { file: string; text: string };
    global: {
        enabled: boolean;
        failClosed: boolean;
        malwareDriver: string;
        quarantineDisk: string;
    };
    archives: Record<string, unknown>;
    images: Record<string, unknown>;
    pdf: Record<string, unknown>;
    html: {
        allowedTags: string[];
        allowedSchemes: string[];
        allowInlineStyles: boolean;
        allowedIframeHosts: string[];
    };
    limits: { maxSizeCeiling: number; forbiddenExtensions: string[] };
    editable: boolean;
}>();

const checkLabels: Record<string, string> = {
    size: 'File size',
    extension: 'Extension allowlist',
    mime: 'MIME verification',
    magic_bytes: 'Magic bytes',
    archive: 'Archive inspection',
    image: 'Image validation',
    pdf: 'PDF inspection',
    malware: 'Malware scan',
    suspicious: 'Suspicious content',
    html: 'HTML sanitization',
    urls: 'URL checks',
};
</script>

<template>
    <Head title="Policies — Content Security" />

    <SecurityAdminLayout>
        <template #title>Policies</template>
        <template #description
            >What each upload slot and text field will accept.</template
        >

        <div
            class="mb-5 flex items-start gap-2 rounded-lg border border-slate-200 bg-white px-4 py-3 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400"
        >
            <Icon
                :name="props.editable ? 'sliders' : 'lock'"
                :size="15"
                class="mt-0.5 shrink-0 text-slate-400"
            />
            <p v-if="props.editable">
                <span class="font-mono">config/content-security.php</span> is
                the baseline. Editing here stores an
                <strong>override</strong> on top of it, recorded in the audit
                log with who changed what — and
                <span class="font-mono">Reset</span> puts a policy back to the
                config value. Two things are never overridable from this screen:
                the <strong>forbidden extensions</strong> below, and the
                maximum-size ceiling.
            </p>
            <p v-else>
                Runtime editing is off (<span class="font-mono"
                    >admin.manage_policies</span
                >). Policies come from
                <span class="font-mono">config/content-security.php</span> only
                — version-controlled, reviewed and deployed, which is the right
                home for a security control.
            </p>
        </div>

        <section class="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div
                class="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900"
            >
                <p class="text-xs text-slate-500 dark:text-slate-400">
                    Scanning
                </p>
                <p
                    class="mt-1 text-sm font-semibold"
                    :class="
                        props.global.enabled
                            ? 'text-emerald-600 dark:text-emerald-400'
                            : 'text-red-600 dark:text-red-400'
                    "
                >
                    {{ props.global.enabled ? 'Enabled' : 'Disabled' }}
                </p>
            </div>
            <div
                class="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900"
            >
                <p class="text-xs text-slate-500 dark:text-slate-400">
                    Fail closed
                </p>
                <p
                    class="mt-1 text-sm font-semibold"
                    :class="
                        props.global.failClosed
                            ? 'text-emerald-600 dark:text-emerald-400'
                            : 'text-amber-600 dark:text-amber-400'
                    "
                >
                    {{ props.global.failClosed ? 'On' : 'Off' }}
                </p>
            </div>
            <div
                class="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900"
            >
                <p class="text-xs text-slate-500 dark:text-slate-400">
                    Malware driver
                </p>
                <p class="mt-1 font-mono text-sm">
                    {{ props.global.malwareDriver }}
                </p>
            </div>
            <div
                class="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900"
            >
                <p class="text-xs text-slate-500 dark:text-slate-400">
                    Quarantine disk
                </p>
                <p class="mt-1 font-mono text-sm">
                    {{ props.global.quarantineDisk }}
                </p>
            </div>
        </section>

        <h2 class="mb-3 text-sm font-semibold">File policies</h2>
        <div class="grid gap-4 lg:grid-cols-2">
            <PolicyEditor
                v-for="policy in props.filePolicies"
                :key="policy.name"
                :policy="policy"
                type="file"
                :is-default="policy.name === props.defaults.file"
                :editable="props.editable"
                :limits="props.limits"
                :check-labels="checkLabels"
            />
        </div>

        <h2 class="mt-8 mb-3 text-sm font-semibold">Text policies</h2>
        <div class="grid gap-4 lg:grid-cols-2">
            <PolicyEditor
                v-for="policy in props.textPolicies"
                :key="policy.name"
                :policy="policy"
                type="text"
                :is-default="policy.name === props.defaults.text"
                :editable="props.editable"
                :limits="props.limits"
                :check-labels="checkLabels"
            />
        </div>

        <h2 class="mt-8 mb-3 text-sm font-semibold">Forbidden extensions</h2>
        <div
            class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
        >
            <p class="mb-3 text-xs text-slate-600 dark:text-slate-400">
                Never accepted, whatever a policy allows, and not editable from
                this screen. These are the formats a misconfigured web server
                may execute — the allowlist is the real control, this is the
                seatbelt behind it. Change them in
                <span class="font-mono">config/content-security.php</span>.
            </p>
            <div class="flex flex-wrap gap-1">
                <span
                    v-for="extension in props.limits.forbiddenExtensions"
                    :key="extension"
                    class="rounded bg-red-50 px-1.5 py-0.5 font-mono text-[10px] text-red-700 dark:bg-red-500/10 dark:text-red-300"
                >
                    .{{ extension }}
                </span>
            </div>
        </div>

        <h2 class="mt-8 mb-3 text-sm font-semibold">HTML sanitizer</h2>
        <div
            class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900"
        >
            <div class="grid gap-4 sm:grid-cols-2">
                <div>
                    <p
                        class="mb-1.5 text-xs text-slate-500 dark:text-slate-400"
                    >
                        Allowed tags
                    </p>
                    <div class="flex flex-wrap gap-1">
                        <span
                            v-for="tag in props.html.allowedTags"
                            :key="tag"
                            class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] dark:bg-slate-800"
                        >
                            {{ tag }}
                        </span>
                    </div>
                </div>
                <div class="space-y-3">
                    <div>
                        <p
                            class="mb-1.5 text-xs text-slate-500 dark:text-slate-400"
                        >
                            Allowed URL schemes
                        </p>
                        <div class="flex flex-wrap gap-1">
                            <span
                                v-for="scheme in props.html.allowedSchemes"
                                :key="scheme"
                                class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] dark:bg-slate-800"
                            >
                                {{ scheme }}:
                            </span>
                        </div>
                    </div>
                    <p class="flex items-center gap-1.5 text-xs">
                        <Icon
                            :name="
                                props.html.allowInlineStyles ? 'alert' : 'check'
                            "
                            :size="13"
                            :class="
                                props.html.allowInlineStyles
                                    ? 'text-amber-600'
                                    : 'text-emerald-600'
                            "
                        />
                        Inline styles
                        {{
                            props.html.allowInlineStyles
                                ? 'allowed'
                                : 'stripped'
                        }}
                    </p>
                    <p class="flex items-center gap-1.5 text-xs">
                        <Icon
                            :name="
                                props.html.allowedIframeHosts.length > 0
                                    ? 'alert'
                                    : 'check'
                            "
                            :size="13"
                            :class="
                                props.html.allowedIframeHosts.length > 0
                                    ? 'text-amber-600'
                                    : 'text-emerald-600'
                            "
                        />
                        {{
                            props.html.allowedIframeHosts.length > 0
                                ? `iframes allowed from ${props.html.allowedIframeHosts.join(', ')}`
                                : 'iframes blocked'
                        }}
                    </p>
                </div>
            </div>
        </div>
    </SecurityAdminLayout>
</template>
