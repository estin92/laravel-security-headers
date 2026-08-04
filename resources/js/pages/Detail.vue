<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { ArrowLeft, TriangleAlert, ArrowRight } from 'lucide-vue-next';
import type { ReportDetail } from '@/lib/types';
import { ApiRequestError, fetchReport } from '@/lib/api';
import { timestamp } from '@/lib/format';
import SanitizationTree from '@/components/SanitizationTree.vue';
import Card from '@/components/ui/Card.vue';
import Badge from '@/components/ui/Badge.vue';

const props = defineProps<{ id: number }>();

const detail = ref<ReportDetail | null>(null);
const error = ref<string | null>(null);
const loading = ref(true);

onMounted(async () => {
    try {
        detail.value = (await fetchReport(props.id)).data;
    } catch (e) {
        error.value = e instanceof ApiRequestError ? e.message : 'Could not load this report.';
    } finally {
        loading.value = false;
    }
});
</script>

<template>
    <div class="space-y-6">
        <a href="#/" class="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
            <ArrowLeft class="size-4" />
            All reports
        </a>

        <div v-if="loading" class="text-muted-foreground">Loading…</div>
        <div v-else-if="error" class="rounded-md border border-destructive/50 bg-destructive/5 text-destructive px-4 py-3 text-sm">
            {{ error }}
        </div>

        <div v-else-if="detail" class="space-y-6">
            <div class="flex flex-wrap items-center gap-3">
                <h1 class="text-2xl font-semibold tracking-tight font-mono">{{ detail.context.type }}</h1>
                <Badge class="border-border bg-secondary text-secondary-foreground">{{ detail.context.protocol }}</Badge>
                <span class="text-sm text-muted-foreground font-mono tabular-nums">{{ timestamp(detail.context.received_at) }}</span>
            </div>

            <div v-if="detail.raw_warning" class="flex gap-3 rounded-lg border border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950/50 p-4">
                <TriangleAlert class="size-5 shrink-0 text-red-600 dark:text-red-400 mt-0.5" />
                <div class="text-sm text-red-800 dark:text-red-300">
                    <p class="font-semibold">Raw storage</p>
                    <p class="mt-0.5 text-red-700 dark:text-red-400">
                        This report was stored without sanitization and may contain exact IP addresses and user agents.
                        An empty action list is not proof the submission contained nothing sensitive.
                    </p>
                </div>
            </div>

            <SanitizationTree :nodes="detail.tree" />

            <div class="flex flex-wrap items-center justify-between gap-4 pt-1">
                <p class="text-xs text-muted-foreground">{{ detail.provenance.label }}</p>
                <a
                    :href="`#/incidents/${detail.context.incident_fingerprint}`"
                    class="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
                >
                    Reports sharing this incident
                    <ArrowRight class="size-4" />
                </a>
            </div>
        </div>
    </div>
</template>
