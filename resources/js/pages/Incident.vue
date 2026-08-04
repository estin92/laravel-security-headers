<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { ArrowLeft } from 'lucide-vue-next';
import type { ReportSummary } from '@/lib/types';
import { ApiRequestError, fetchIncident } from '@/lib/api';
import { timestamp } from '@/lib/format';
import Card from '@/components/ui/Card.vue';
import Badge from '@/components/ui/Badge.vue';
import Button from '@/components/ui/Button.vue';
import Table from '@/components/ui/Table.vue';
import { TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/TableParts';

const props = defineProps<{ fingerprint: string }>();

const reports = ref<ReportSummary[]>([]);
const nextCursor = ref<string | null>(null);
const error = ref<string | null>(null);
const loading = ref(false);

function open(id: number): void {
    window.location.hash = `#/reports/${id}`;
}

async function load(): Promise<void> {
    loading.value = true;
    error.value = null;

    try {
        const feed = await fetchIncident(props.fingerprint, nextCursor.value ?? undefined);
        reports.value = [...reports.value, ...feed.data];
        nextCursor.value = feed.next_cursor;
    } catch (e) {
        error.value = e instanceof ApiRequestError ? e.message : 'Could not load this incident.';
    } finally {
        loading.value = false;
    }
}

onMounted(() => void load());
</script>

<template>
    <div class="space-y-6">
        <a href="#/" class="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
            <ArrowLeft class="size-4" />
            All reports
        </a>

        <div>
            <h1 class="text-2xl font-semibold tracking-tight">Incident</h1>
            <p class="text-xs text-muted-foreground mt-1 font-mono break-all">{{ fingerprint }}</p>
        </div>

        <div v-if="error" class="rounded-md border border-destructive/50 bg-destructive/5 text-destructive px-4 py-3 text-sm">
            {{ error }}
        </div>

        <Card class="overflow-hidden">
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead>Type</TableHead>
                        <TableHead class="text-right">Received</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    <TableRow v-for="report in reports" :key="report.id" class="cursor-pointer" @click="open(report.id)">
                        <TableCell>
                            <Badge class="border-border bg-secondary text-secondary-foreground font-mono">{{ report.type }}</Badge>
                        </TableCell>
                        <TableCell class="text-right text-muted-foreground tabular-nums">{{ timestamp(report.received_at) }}</TableCell>
                    </TableRow>
                </TableBody>
            </Table>
        </Card>

        <div v-if="nextCursor" class="flex justify-center">
            <Button variant="outline" :disabled="loading" @click="load">
                {{ loading ? 'Loading…' : 'Load more' }}
            </Button>
        </div>
    </div>
</template>
