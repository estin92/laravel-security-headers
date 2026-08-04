<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import type { ReportSummary } from '@/lib/types';
import { ApiRequestError, type FeedQuery, fetchFeed } from '@/lib/api';
import { timestamp } from '@/lib/format';
import Card from '@/components/ui/Card.vue';
import Input from '@/components/ui/Input.vue';
import Button from '@/components/ui/Button.vue';
import Badge from '@/components/ui/Badge.vue';
import Table from '@/components/ui/Table.vue';
import { TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/TableParts';

const reports = ref<ReportSummary[]>([]);
const nextCursor = ref<string | null>(null);
const error = ref<string | null>(null);
const loading = ref(false);
let requestToken = 0;

const filters = reactive({ type: '', protocol: '', url_origin: '' });

function currentFilters(): FeedQuery {
    return {
        type: filters.type || undefined,
        protocol: filters.protocol || undefined,
        url_origin: filters.url_origin || undefined,
    };
}

async function load(reset: boolean): Promise<void> {
    const token = ++requestToken;
    loading.value = true;
    error.value = null;

    try {
        const params: FeedQuery = { ...currentFilters(), limit: 50 };
        if (!reset && nextCursor.value) {
            params.cursor = nextCursor.value;
        }

        const feed = await fetchFeed(params);
        if (token !== requestToken) {
            return;
        }

        reports.value = reset ? feed.data : [...reports.value, ...feed.data];
        nextCursor.value = feed.next_cursor;
    } catch (e) {
        if (token !== requestToken) {
            return;
        }

        error.value = e instanceof ApiRequestError ? e.message : 'Could not load reports.';
    } finally {
        if (token === requestToken) {
            loading.value = false;
        }
    }
}

function applyFilters(): void {
    nextCursor.value = null;
    void load(true);
}

function open(id: number): void {
    window.location.hash = `#/reports/${id}`;
}

onMounted(() => void load(true));
</script>

<template>
    <div class="space-y-6">
        <div>
            <h1 class="text-2xl font-semibold tracking-tight">Reports</h1>
            <p class="text-sm text-muted-foreground mt-1">Browser security violations reported to this site.</p>
        </div>

        <Card class="p-4">
            <div class="grid grid-cols-1 sm:grid-cols-[1fr_1fr_1fr_auto] gap-3 items-end">
                <label class="space-y-1.5">
                    <span class="text-xs font-medium text-muted-foreground">Type</span>
                    <Input v-model="filters.type" placeholder="csp-violation" @keyup.enter="applyFilters" />
                </label>
                <label class="space-y-1.5">
                    <span class="text-xs font-medium text-muted-foreground">Origin</span>
                    <Input v-model="filters.url_origin" placeholder="https://…" @keyup.enter="applyFilters" />
                </label>
                <label class="space-y-1.5">
                    <span class="text-xs font-medium text-muted-foreground">Protocol</span>
                    <Input v-model="filters.protocol" placeholder="reporting-api" @keyup.enter="applyFilters" />
                </label>
                <Button @click="applyFilters">Apply</Button>
            </div>
        </Card>

        <div v-if="error" class="rounded-md border border-destructive/50 bg-destructive/5 text-destructive px-4 py-3 text-sm">
            {{ error }}
        </div>

        <Card class="overflow-hidden">
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead>Type</TableHead>
                        <TableHead>Origin</TableHead>
                        <TableHead>Protocol</TableHead>
                        <TableHead class="text-right">Received</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    <TableRow
                        v-for="report in reports"
                        :key="report.id"
                        class="cursor-pointer"
                        @click="open(report.id)"
                    >
                        <TableCell>
                            <Badge class="border-border bg-secondary text-secondary-foreground font-mono">{{ report.type }}</Badge>
                        </TableCell>
                        <TableCell class="text-muted-foreground truncate max-w-[18rem]">{{ report.url_origin ?? '—' }}</TableCell>
                        <TableCell class="text-muted-foreground">{{ report.protocol }}</TableCell>
                        <TableCell class="text-right text-muted-foreground tabular-nums">{{ timestamp(report.received_at) }}</TableCell>
                    </TableRow>
                    <TableRow v-if="reports.length === 0 && !loading">
                        <TableCell class="text-center text-muted-foreground py-10" colspan="4">No reports match these filters.</TableCell>
                    </TableRow>
                </TableBody>
            </Table>
        </Card>

        <div v-if="nextCursor" class="flex justify-center">
            <Button variant="outline" :disabled="loading" @click="load(false)">
                {{ loading ? 'Loading…' : 'Load more' }}
            </Button>
        </div>
    </div>
</template>
